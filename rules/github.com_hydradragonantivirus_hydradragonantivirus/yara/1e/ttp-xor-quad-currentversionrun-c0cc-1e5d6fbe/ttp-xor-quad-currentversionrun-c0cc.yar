rule TTP_XOR_QUAD_CurrentVersionRun_c0cc {
  strings:
    $key_c0cc = { 93 a3 [2] b7 ad [2] 9c 81 [2] b2 a3 [2] a6 b8 [2] a9 a2 [2] b7 bf [2] b5 be [2] ae b8 [2] b2 bf [2] ae 90 }

  condition:
    any of them
}