rule TTP_XOR_QUAD_CurrentVersionRun_b042 {
  strings:
    $key_b042 = { e3 2d [2] c7 23 [2] ec 0f [2] c2 2d [2] d6 36 [2] d9 2c [2] c7 31 [2] c5 30 [2] de 36 [2] c2 31 [2] de 1e }

  condition:
    any of them
}