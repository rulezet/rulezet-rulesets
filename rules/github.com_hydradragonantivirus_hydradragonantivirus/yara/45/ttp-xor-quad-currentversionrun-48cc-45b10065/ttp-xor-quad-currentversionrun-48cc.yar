rule TTP_XOR_QUAD_CurrentVersionRun_48cc {
  strings:
    $key_48cc = { 1b a3 [2] 3f ad [2] 14 81 [2] 3a a3 [2] 2e b8 [2] 21 a2 [2] 3f bf [2] 3d be [2] 26 b8 [2] 3a bf [2] 26 90 }

  condition:
    any of them
}