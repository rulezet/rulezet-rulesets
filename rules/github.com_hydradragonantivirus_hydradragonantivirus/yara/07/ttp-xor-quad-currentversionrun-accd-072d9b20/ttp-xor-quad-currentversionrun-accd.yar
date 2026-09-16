rule TTP_XOR_QUAD_CurrentVersionRun_accd {
  strings:
    $key_accd = { ff a2 [2] db ac [2] f0 80 [2] de a2 [2] ca b9 [2] c5 a3 [2] db be [2] d9 bf [2] c2 b9 [2] de be [2] c2 91 }

  condition:
    any of them
}