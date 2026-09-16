rule TTP_XOR_QUAD_CurrentVersionRun_b066 {
  strings:
    $key_b066 = { e3 09 [2] c7 07 [2] ec 2b [2] c2 09 [2] d6 12 [2] d9 08 [2] c7 15 [2] c5 14 [2] de 12 [2] c2 15 [2] de 3a }

  condition:
    any of them
}