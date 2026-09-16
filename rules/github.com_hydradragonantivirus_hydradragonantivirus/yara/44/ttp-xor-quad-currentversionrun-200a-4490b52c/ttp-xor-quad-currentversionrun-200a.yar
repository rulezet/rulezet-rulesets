rule TTP_XOR_QUAD_CurrentVersionRun_200a {
  strings:
    $key_200a = { 73 65 [2] 57 6b [2] 7c 47 [2] 52 65 [2] 46 7e [2] 49 64 [2] 57 79 [2] 55 78 [2] 4e 7e [2] 52 79 [2] 4e 56 }

  condition:
    any of them
}