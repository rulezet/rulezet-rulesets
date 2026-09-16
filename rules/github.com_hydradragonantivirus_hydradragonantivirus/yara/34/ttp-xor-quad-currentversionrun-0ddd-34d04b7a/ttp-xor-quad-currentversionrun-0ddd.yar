rule TTP_XOR_QUAD_CurrentVersionRun_0ddd {
  strings:
    $key_0ddd = { 5e b2 [2] 7a bc [2] 51 90 [2] 7f b2 [2] 6b a9 [2] 64 b3 [2] 7a ae [2] 78 af [2] 63 a9 [2] 7f ae [2] 63 81 }

  condition:
    any of them
}