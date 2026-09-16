rule TTP_XOR_QUAD_CurrentVersionRun_efdd {
  strings:
    $key_efdd = { bc b2 [2] 98 bc [2] b3 90 [2] 9d b2 [2] 89 a9 [2] 86 b3 [2] 98 ae [2] 9a af [2] 81 a9 [2] 9d ae [2] 81 81 }

  condition:
    any of them
}