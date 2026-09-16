rule TTP_XOR_QUAD_CurrentVersionRun_163f {
  strings:
    $key_163f = { 45 50 [2] 61 5e [2] 4a 72 [2] 64 50 [2] 70 4b [2] 7f 51 [2] 61 4c [2] 63 4d [2] 78 4b [2] 64 4c [2] 78 63 }

  condition:
    any of them
}