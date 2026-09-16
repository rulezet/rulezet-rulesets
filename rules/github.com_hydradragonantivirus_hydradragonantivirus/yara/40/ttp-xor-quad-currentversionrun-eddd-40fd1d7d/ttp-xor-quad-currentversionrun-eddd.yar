rule TTP_XOR_QUAD_CurrentVersionRun_eddd {
  strings:
    $key_eddd = { be b2 [2] 9a bc [2] b1 90 [2] 9f b2 [2] 8b a9 [2] 84 b3 [2] 9a ae [2] 98 af [2] 83 a9 [2] 9f ae [2] 83 81 }

  condition:
    any of them
}