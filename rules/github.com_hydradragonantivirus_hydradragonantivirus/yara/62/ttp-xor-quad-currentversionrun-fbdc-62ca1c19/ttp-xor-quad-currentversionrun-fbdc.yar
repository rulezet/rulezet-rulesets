rule TTP_XOR_QUAD_CurrentVersionRun_fbdc {
  strings:
    $key_fbdc = { a8 b3 [2] 8c bd [2] a7 91 [2] 89 b3 [2] 9d a8 [2] 92 b2 [2] 8c af [2] 8e ae [2] 95 a8 [2] 89 af [2] 95 80 }

  condition:
    any of them
}