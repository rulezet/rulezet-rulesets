rule TTP_XOR_QUAD_CurrentVersionRun_adbf {
  strings:
    $key_adbf = { fe d0 [2] da de [2] f1 f2 [2] df d0 [2] cb cb [2] c4 d1 [2] da cc [2] d8 cd [2] c3 cb [2] df cc [2] c3 e3 }

  condition:
    any of them
}