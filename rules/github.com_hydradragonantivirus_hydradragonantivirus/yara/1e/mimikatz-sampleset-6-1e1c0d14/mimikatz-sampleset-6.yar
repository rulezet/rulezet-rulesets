rule Mimikatz_SampleSet_6: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash        = "739c80bac405eb1b0ebbe10a75515ff1"

  strings:
    $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><tr"
    $s2 = "Erreur : impossible d'ouvrir le bureau cible (" fullword

  condition:
    all of them
}