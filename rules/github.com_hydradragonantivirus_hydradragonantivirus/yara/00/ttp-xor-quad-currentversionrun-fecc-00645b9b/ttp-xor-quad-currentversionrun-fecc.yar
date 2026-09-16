rule TTP_XOR_QUAD_CurrentVersionRun_fecc {
  strings:
    $key_fecc = { ad a3 [2] 89 ad [2] a2 81 [2] 8c a3 [2] 98 b8 [2] 97 a2 [2] 89 bf [2] 8b be [2] 90 b8 [2] 8c bf [2] 90 90 }

  condition:
    any of them
}