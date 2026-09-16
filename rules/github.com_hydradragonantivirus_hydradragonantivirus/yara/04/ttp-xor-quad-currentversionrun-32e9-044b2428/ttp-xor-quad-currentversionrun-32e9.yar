rule TTP_XOR_QUAD_CurrentVersionRun_32e9 {
  strings:
    $key_32e9 = { 61 86 [2] 45 88 [2] 6e a4 [2] 40 86 [2] 54 9d [2] 5b 87 [2] 45 9a [2] 47 9b [2] 5c 9d [2] 40 9a [2] 5c b5 }

  condition:
    any of them
}