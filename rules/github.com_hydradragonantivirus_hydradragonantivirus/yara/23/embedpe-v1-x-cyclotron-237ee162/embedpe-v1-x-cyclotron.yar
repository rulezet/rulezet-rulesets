import "pe"
rule EmbedPE_V1_X____cyclotron {
  strings:
    $a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00 }

  condition:
    $a0 at pe.entry_point
}