rule TTP_XOR_QUAD_CurrentVersionRun_7e0f {
  strings:
    $key_7e0f = { 2d 60 [2] 09 6e [2] 22 42 [2] 0c 60 [2] 18 7b [2] 17 61 [2] 09 7c [2] 0b 7d [2] 10 7b [2] 0c 7c [2] 10 53 }

  condition:
    any of them
}