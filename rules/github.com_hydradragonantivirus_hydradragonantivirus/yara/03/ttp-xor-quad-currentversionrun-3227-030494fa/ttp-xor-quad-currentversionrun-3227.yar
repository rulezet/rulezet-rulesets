rule TTP_XOR_QUAD_CurrentVersionRun_3227 {
  strings:
    $key_3227 = { 61 48 [2] 45 46 [2] 6e 6a [2] 40 48 [2] 54 53 [2] 5b 49 [2] 45 54 [2] 47 55 [2] 5c 53 [2] 40 54 [2] 5c 7b }

  condition:
    any of them
}