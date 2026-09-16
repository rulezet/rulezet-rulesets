rule TTP_XOR_QUAD_CurrentVersionRun_78cc {
  strings:
    $key_78cc = { 2b a3 [2] 0f ad [2] 24 81 [2] 0a a3 [2] 1e b8 [2] 11 a2 [2] 0f bf [2] 0d be [2] 16 b8 [2] 0a bf [2] 16 90 }

  condition:
    any of them
}