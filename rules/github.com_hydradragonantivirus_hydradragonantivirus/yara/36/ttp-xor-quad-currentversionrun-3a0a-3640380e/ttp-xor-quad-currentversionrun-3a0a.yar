rule TTP_XOR_QUAD_CurrentVersionRun_3a0a {
  strings:
    $key_3a0a = { 69 65 [2] 4d 6b [2] 66 47 [2] 48 65 [2] 5c 7e [2] 53 64 [2] 4d 79 [2] 4f 78 [2] 54 7e [2] 48 79 [2] 54 56 }

  condition:
    any of them
}