rule TTP_XOR_QUAD_CurrentVersionRun_c5cc {
  strings:
    $key_c5cc = { 96 a3 [2] b2 ad [2] 99 81 [2] b7 a3 [2] a3 b8 [2] ac a2 [2] b2 bf [2] b0 be [2] ab b8 [2] b7 bf [2] ab 90 }

  condition:
    any of them
}