rule TTP_XOR_QUAD_CurrentVersionRun_093b {
  strings:
    $key_093b = { 5a 54 [2] 7e 5a [2] 55 76 [2] 7b 54 [2] 6f 4f [2] 60 55 [2] 7e 48 [2] 7c 49 [2] 67 4f [2] 7b 48 [2] 67 67 }

  condition:
    any of them
}