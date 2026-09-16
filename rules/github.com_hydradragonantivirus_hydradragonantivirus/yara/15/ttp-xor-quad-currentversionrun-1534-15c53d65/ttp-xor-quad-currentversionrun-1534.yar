rule TTP_XOR_QUAD_CurrentVersionRun_1534 {
  strings:
    $key_1534 = { 46 5b [2] 62 55 [2] 49 79 [2] 67 5b [2] 73 40 [2] 7c 5a [2] 62 47 [2] 60 46 [2] 7b 40 [2] 67 47 [2] 7b 68 }

  condition:
    any of them
}