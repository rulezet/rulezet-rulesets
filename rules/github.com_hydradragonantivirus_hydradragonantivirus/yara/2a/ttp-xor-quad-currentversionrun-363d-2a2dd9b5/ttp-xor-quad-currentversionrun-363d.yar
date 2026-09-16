rule TTP_XOR_QUAD_CurrentVersionRun_363d {
  strings:
    $key_363d = { 65 52 [2] 41 5c [2] 6a 70 [2] 44 52 [2] 50 49 [2] 5f 53 [2] 41 4e [2] 43 4f [2] 58 49 [2] 44 4e [2] 58 61 }

  condition:
    any of them
}