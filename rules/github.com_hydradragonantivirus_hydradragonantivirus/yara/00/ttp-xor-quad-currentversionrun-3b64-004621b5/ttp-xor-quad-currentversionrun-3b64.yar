rule TTP_XOR_QUAD_CurrentVersionRun_3b64 {
  strings:
    $key_3b64 = { 68 0b [2] 4c 05 [2] 67 29 [2] 49 0b [2] 5d 10 [2] 52 0a [2] 4c 17 [2] 4e 16 [2] 55 10 [2] 49 17 [2] 55 38 }

  condition:
    any of them
}