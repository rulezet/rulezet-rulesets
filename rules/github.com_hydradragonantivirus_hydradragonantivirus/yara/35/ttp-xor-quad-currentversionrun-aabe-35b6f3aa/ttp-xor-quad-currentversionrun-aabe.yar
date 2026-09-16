rule TTP_XOR_QUAD_CurrentVersionRun_aabe {
  strings:
    $key_aabe = { f9 d1 [2] dd df [2] f6 f3 [2] d8 d1 [2] cc ca [2] c3 d0 [2] dd cd [2] df cc [2] c4 ca [2] d8 cd [2] c4 e2 }

  condition:
    any of them
}