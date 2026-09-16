rule TTP_XOR_QUAD_CurrentVersionRun_c1cc {
  strings:
    $key_c1cc = { 92 a3 [2] b6 ad [2] 9d 81 [2] b3 a3 [2] a7 b8 [2] a8 a2 [2] b6 bf [2] b4 be [2] af b8 [2] b3 bf [2] af 90 }

  condition:
    any of them
}