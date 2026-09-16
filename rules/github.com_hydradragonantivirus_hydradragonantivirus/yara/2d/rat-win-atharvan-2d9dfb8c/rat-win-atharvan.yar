rule rat_win_atharvan {
  meta:
    id             = "61347490-d281-4892-adba-89cf6187545f"
    version        = "1.0"
    description    = "Detect Atharvan RAT"
    author         = "Sekoia.io"
    creation_date  = "2023-02-23"
    classification = "TLP:CLEAR"

  strings:
    $s1 = "D:\\rang\\TOOL\\3RAT"

  condition:
    all of them
}