rule TTP_XOR_QUAD_CurrentVersionRun_f9cc {
  strings:
    $key_f9cc = { aa a3 [2] 8e ad [2] a5 81 [2] 8b a3 [2] 9f b8 [2] 90 a2 [2] 8e bf [2] 8c be [2] 97 b8 [2] 8b bf [2] 97 90 }

  condition:
    any of them
}