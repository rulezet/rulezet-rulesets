rule TTP_XOR_QUAD_CurrentVersionRun_322b {
  strings:
    $key_322b = { 61 44 [2] 45 4a [2] 6e 66 [2] 40 44 [2] 54 5f [2] 5b 45 [2] 45 58 [2] 47 59 [2] 5c 5f [2] 40 58 [2] 5c 77 }

  condition:
    any of them
}