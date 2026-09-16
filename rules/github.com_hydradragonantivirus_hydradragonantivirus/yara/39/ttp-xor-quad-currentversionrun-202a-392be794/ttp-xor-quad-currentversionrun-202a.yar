rule TTP_XOR_QUAD_CurrentVersionRun_202a {
  strings:
    $key_202a = { 73 45 [2] 57 4b [2] 7c 67 [2] 52 45 [2] 46 5e [2] 49 44 [2] 57 59 [2] 55 58 [2] 4e 5e [2] 52 59 [2] 4e 76 }

  condition:
    any of them
}