rule TTP_XOR_QUAD_CurrentVersionRun_580f {
  strings:
    $key_580f = { 0b 60 [2] 2f 6e [2] 04 42 [2] 2a 60 [2] 3e 7b [2] 31 61 [2] 2f 7c [2] 2d 7d [2] 36 7b [2] 2a 7c [2] 36 53 }

  condition:
    any of them
}