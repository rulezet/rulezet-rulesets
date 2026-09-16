rule TTP_XOR_QUAD_CurrentVersionRun_0732 {
  strings:
    $key_0732 = { 54 5d [2] 70 53 [2] 5b 7f [2] 75 5d [2] 61 46 [2] 6e 5c [2] 70 41 [2] 72 40 [2] 69 46 [2] 75 41 [2] 69 6e }

  condition:
    any of them
}