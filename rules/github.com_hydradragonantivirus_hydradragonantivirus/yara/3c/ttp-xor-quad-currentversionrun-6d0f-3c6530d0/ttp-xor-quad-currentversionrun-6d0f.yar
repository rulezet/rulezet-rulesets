rule TTP_XOR_QUAD_CurrentVersionRun_6d0f {
  strings:
    $key_6d0f = { 3e 60 [2] 1a 6e [2] 31 42 [2] 1f 60 [2] 0b 7b [2] 04 61 [2] 1a 7c [2] 18 7d [2] 03 7b [2] 1f 7c [2] 03 53 }

  condition:
    any of them
}