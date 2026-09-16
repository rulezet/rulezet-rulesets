rule TTP_XOR_QUAD_CurrentVersionRun_0227 {
  strings:
    $key_0227 = { 51 48 [2] 75 46 [2] 5e 6a [2] 70 48 [2] 64 53 [2] 6b 49 [2] 75 54 [2] 77 55 [2] 6c 53 [2] 70 54 [2] 6c 7b }

  condition:
    any of them
}