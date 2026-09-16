rule TTP_XOR_QUAD_CurrentVersionRun_1bdc {
  strings:
    $key_1bdc = { 48 b3 [2] 6c bd [2] 47 91 [2] 69 b3 [2] 7d a8 [2] 72 b2 [2] 6c af [2] 6e ae [2] 75 a8 [2] 69 af [2] 75 80 }

  condition:
    any of them
}