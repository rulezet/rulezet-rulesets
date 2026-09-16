rule TTP_XOR_QUAD_CurrentVersionRun_fbdd {
  strings:
    $key_fbdd = { a8 b2 [2] 8c bc [2] a7 90 [2] 89 b2 [2] 9d a9 [2] 92 b3 [2] 8c ae [2] 8e af [2] 95 a9 [2] 89 ae [2] 95 81 }

  condition:
    any of them
}