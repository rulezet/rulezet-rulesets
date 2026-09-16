rule TTP_XOR_QUAD_CurrentVersionRun_9acd {
  strings:
    $key_9acd = { c9 a2 [2] ed ac [2] c6 80 [2] e8 a2 [2] fc b9 [2] f3 a3 [2] ed be [2] ef bf [2] f4 b9 [2] e8 be [2] f4 91 }

  condition:
    any of them
}