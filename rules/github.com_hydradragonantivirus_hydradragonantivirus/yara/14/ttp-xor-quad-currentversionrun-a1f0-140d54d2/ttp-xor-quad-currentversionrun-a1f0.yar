rule TTP_XOR_QUAD_CurrentVersionRun_a1f0 {
  strings:
    $key_a1f0 = { f2 9f [2] d6 91 [2] fd bd [2] d3 9f [2] c7 84 [2] c8 9e [2] d6 83 [2] d4 82 [2] cf 84 [2] d3 83 [2] cf ac }

  condition:
    any of them
}