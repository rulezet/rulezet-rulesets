rule TTP_XOR_QUAD_CurrentVersionRun_2bdc {
  strings:
    $key_2bdc = { 78 b3 [2] 5c bd [2] 77 91 [2] 59 b3 [2] 4d a8 [2] 42 b2 [2] 5c af [2] 5e ae [2] 45 a8 [2] 59 af [2] 45 80 }

  condition:
    any of them
}