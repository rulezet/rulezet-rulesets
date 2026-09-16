rule TTP_XOR_QUAD_CurrentVersionRun_3a0f {
  strings:
    $key_3a0f = { 69 60 [2] 4d 6e [2] 66 42 [2] 48 60 [2] 5c 7b [2] 53 61 [2] 4d 7c [2] 4f 7d [2] 54 7b [2] 48 7c [2] 54 53 }

  condition:
    any of them
}