rule TTP_XOR_QUAD_CurrentVersionRun_dccd {
  strings:
    $key_dccd = { 8f a2 [2] ab ac [2] 80 80 [2] ae a2 [2] ba b9 [2] b5 a3 [2] ab be [2] a9 bf [2] b2 b9 [2] ae be [2] b2 91 }

  condition:
    any of them
}