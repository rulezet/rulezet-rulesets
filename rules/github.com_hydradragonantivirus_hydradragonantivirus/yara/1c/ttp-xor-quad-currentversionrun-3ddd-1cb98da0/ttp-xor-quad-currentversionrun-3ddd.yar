rule TTP_XOR_QUAD_CurrentVersionRun_3ddd {
  strings:
    $key_3ddd = { 6e b2 [2] 4a bc [2] 61 90 [2] 4f b2 [2] 5b a9 [2] 54 b3 [2] 4a ae [2] 48 af [2] 53 a9 [2] 4f ae [2] 53 81 }

  condition:
    any of them
}