rule TTP_XOR_QUAD_CurrentVersionRun_4b64 {
  strings:
    $key_4b64 = { 18 0b [2] 3c 05 [2] 17 29 [2] 39 0b [2] 2d 10 [2] 22 0a [2] 3c 17 [2] 3e 16 [2] 25 10 [2] 39 17 [2] 25 38 }

  condition:
    any of them
}