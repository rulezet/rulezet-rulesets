rule TTP_XOR_QUAD_CurrentVersionRun_363f {
  strings:
    $key_363f = { 65 50 [2] 41 5e [2] 6a 72 [2] 44 50 [2] 50 4b [2] 5f 51 [2] 41 4c [2] 43 4d [2] 58 4b [2] 44 4c [2] 58 63 }

  condition:
    any of them
}