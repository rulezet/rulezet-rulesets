rule TTP_XOR_QUAD_CurrentVersionRun_08cc {
  strings:
    $key_08cc = { 5b a3 [2] 7f ad [2] 54 81 [2] 7a a3 [2] 6e b8 [2] 61 a2 [2] 7f bf [2] 7d be [2] 66 b8 [2] 7a bf [2] 66 90 }

  condition:
    any of them
}