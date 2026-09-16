rule TTP_XOR_QUAD_CurrentVersionRun_abcd {
  strings:
    $key_abcd = { f8 a2 [2] dc ac [2] f7 80 [2] d9 a2 [2] cd b9 [2] c2 a3 [2] dc be [2] de bf [2] c5 b9 [2] d9 be [2] c5 91 }

  condition:
    any of them
}