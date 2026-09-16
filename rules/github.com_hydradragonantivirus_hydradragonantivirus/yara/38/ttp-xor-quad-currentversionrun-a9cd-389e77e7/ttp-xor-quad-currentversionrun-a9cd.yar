rule TTP_XOR_QUAD_CurrentVersionRun_a9cd {
  strings:
    $key_a9cd = { fa a2 [2] de ac [2] f5 80 [2] db a2 [2] cf b9 [2] c0 a3 [2] de be [2] dc bf [2] c7 b9 [2] db be [2] c7 91 }

  condition:
    any of them
}