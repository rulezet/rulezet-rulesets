rule TTP_XOR_QUAD_CurrentVersionRun_597d {
  strings:
    $key_597d = { 0a 12 [2] 2e 1c [2] 05 30 [2] 2b 12 [2] 3f 09 [2] 30 13 [2] 2e 0e [2] 2c 0f [2] 37 09 [2] 2b 0e [2] 37 21 }

  condition:
    any of them
}