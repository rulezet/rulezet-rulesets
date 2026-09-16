rule TTP_XOR_QUAD_CurrentVersionRun_623b {
  strings:
    $key_623b = { 31 54 [2] 15 5a [2] 3e 76 [2] 10 54 [2] 04 4f [2] 0b 55 [2] 15 48 [2] 17 49 [2] 0c 4f [2] 10 48 [2] 0c 67 }

  condition:
    any of them
}