rule TTP_XOR_QUAD_CurrentVersionRun_161f {
  strings:
    $key_161f = { 45 70 [2] 61 7e [2] 4a 52 [2] 64 70 [2] 70 6b [2] 7f 71 [2] 61 6c [2] 63 6d [2] 78 6b [2] 64 6c [2] 78 43 }

  condition:
    any of them
}