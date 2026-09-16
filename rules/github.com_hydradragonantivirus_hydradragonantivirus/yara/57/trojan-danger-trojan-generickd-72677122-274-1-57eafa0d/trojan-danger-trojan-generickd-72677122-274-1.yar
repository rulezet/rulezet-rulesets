rule Trojan_Danger_Trojan_GenericKD_72677122_274_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_274_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d2afefedb66c12c80fcb4ab16dd98ba57d038876e25a2eeb3fef99c5b4efc9"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2  = "Warning:CScanToSugarSyncApp::Exec_Configuration:Get long path name failed." fullword wide
    $s3  = "Error:CScanToSugarSyncApp::Exec_FileCopy: Getting default destination folder path is failed!" fullword wide
    $s4  = "Error:CScanToSugarSyncApp::Exec_FileCopy: Failed to get the window position." fullword wide
    $s5  = "CScanToSugarSyncApp::Exec_Filecopy:Creating the window of preview dialog is failed!" fullword wide
    $s6  = "Error:CScanToSugarSyncApp::Exec_Configuration: Failed to read setting ini file." fullword wide
    $s7  = "Error:CScanToSugarSyncApp::Exec_Configuration: Failed to save setting info." fullword wide
    $s8  = "Error:CScanToSugarSyncApp::Exec_FileCopy: The length of the path has exceed %d." fullword wide
    $s9  = "Start:CScanToSugarSyncApp::Exec_Configuration" fullword wide
    $s10 = "Error:CScanToSugarSyncApp::Exec_FileCopy: Failed to load folder history." fullword wide
    $s11 = "Error:CScanToSugarSyncApp::Exec_FileCopy: Create preview failed." fullword wide
    $s12 = "Error:CScanToSugarSyncApp::Exec_FileCopy: Failed to save setting info." fullword wide
    $s13 = "Error:CScanToSugarSyncApp::InitInstance: Failed to read ini file. [Section]=%s, [Key]=%s" fullword wide
    $s14 = "Info :CScanToSugarSyncApp::InitInstance: Mutex already exists!" fullword wide
    $s15 = "Error:CScanToSugarSyncApp::InitInstance: Command No Parameter" fullword wide
    $s16 = "Error:CScanToSugarSyncApp::GetDropboxInitFolder: Reading the first line text data of host.db is failed!" fullword wide
    $s17 = "Error:CScanToSugarSyncApp::GetDropboxInitFolder: Reading the second line text data of host.db is failed!" fullword wide
    $s18 = "Start:CScanToSugarSyncApp::Exec_FileCopy" fullword wide
    $s19 = "Error:CScanToSugarSyncApp::GetDropboxInitFolder: host.db is failed to open!" fullword wide
    $s20 = "Error:CScanToSugarSyncApp::GetDropboxInitFolder: Decoding the Dropbox destination folder path From base64 is failed!" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}