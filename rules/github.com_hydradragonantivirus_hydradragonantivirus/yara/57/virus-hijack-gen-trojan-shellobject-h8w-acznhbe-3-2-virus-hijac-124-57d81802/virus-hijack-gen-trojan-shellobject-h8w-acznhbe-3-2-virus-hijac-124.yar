import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_3_2_Virus_Hijac_124 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58b836a801340413e865e1b44527f2a6d769c9c379abe237e559d1bf535ae1c8"
    hash2       = "39bb2cb891205f1e07366c1cbcffb9c4e02298929b19cb8544e10f0ae7341199"

  strings:
    $s1  = " disponible, executeu ISScript.msi, o poseu-vos en contacte amb el personal de suport t" fullword ascii
    $s2  = "lid.El nom d'usuari no pot ser buit i ha d'estar en el format DOMINI\\Nom d'usuari.Error en carregar o crear el fitxer INI al di" ascii
    $s3  = " 3.0 o superior.Error en crear el fitxer XML [2] [3]Error en carregar els servidors.Error en carregar el NetApi32.DLL. El ISNetA" ascii
    $s4  = "ectori TEMP de l'usuari.No s'ha carregat el ISNetAPI.dll o hi ha hagut un error en carregar el dll. S'ha d'haver carregat aquest" ascii
    $s5  = ". Comproveu que el dll sigui al directori SUPPORTDIR Error en suprimir el fitxer INI que cont" fullword ascii
    $s6  = " Comproveu que el servidor especificat existeix. El nom del servidor no pot ser buit. Error no especificat del ISNetApi.dll.La m" ascii
    $s7  = " posterior. Visiteu www.microsoft.com per actualitzar Internet Explorer.LC_UNSUPPORTED_OSLC_UNSUPPORTED_OS_1Aquesta aplicaci" fullword ascii
    $s8  = " del fitxer [2] pel fitxer [3] en reiniciar el sistema.  Verifiqueu que teniu permisos d'escriptura al fitxer [3].Error en supri" ascii
    $s9  = " [BrandName] sigui el visualitzador de PDF predeterminatOwnership_ChkBox_Win10Estableix el programari [BrandName] com a visor PD" ascii
    $s10 = "pi.dll ha de tenir el NetApi32.DLL carregat correctament i requereix un sistema operatiu basat en NT.No s'ha trobat el servidor." ascii
    $s11 = " ha fallat.Producte: [2] -- [3]Podeu restaurar el sistema a l'estat anterior o continuar posteriorment amb la instal" fullword ascii
    $s12 = " COM+ [2]. No s'ha pogut crear un objecte System.EnterpriseServices.RegistrationHelper. Per registrar els components del servei " ascii
    $s13 = "lat els serveis de component Component Services (COM+ 1.0).  Aquesta instal" fullword ascii
    $s14 = " COM+ [2]. No s'ha pogut crear un objecte System.EnterpriseServices.RegistrationHelper. Per registrar els components del servei " ascii
    $s15 = "nims del sistema a http://www.adobe.com/go/reader_system_reqs_es.ManufacturerNom de la vostra empresaOLE_VERB_OPEN&Obre,0,2OpenW" ascii
    $s16 = " 3.0 o superior.Error en crear el fitxer XML [2] [3]Error en carregar els servidors.Error en carregar el NetApi32.DLL. El ISNetA" ascii
    $s17 = "lat.SFX_DLG_ERR_DISK_SPACEHi ha poc espai al disc. Allibereu [DISK_SPACE] MB d'espai al disc i torneu a executar l'instal" fullword ascii
    $s18 = "n incompatibles.Sense espai en disc - Volum: [2]; espai necessari: [3] Kb; espai disponible: [4] Kb.  Si l'opci" fullword ascii
    $s19 = ".  {{Error de sistema: [3]}}No s'ha pogut crear la clau [2]. {{ Error de sistema [3].}}No s'ha pogut obrir la clau: [2]. {{ Erro" ascii
    $s20 = " requereix actualitzacions de seguretat, disponibles a www.adobe.com.  Adobe recomana que es baixi i s'instal" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b10d16eedb1085ef7262dfc4ab03be6f" and (8 of them)
    ) or (all of them)
}