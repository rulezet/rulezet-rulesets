rule tree7 {
  strings:
    $s0    = "getRequiredClass" fullword
    $s1    = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s2    = "sizeOfItemAtPath" fullword
    $s3    = "filesystem14basic" fullword
    $s4    = "9allocatorIyEEEES4" fullword
    $s5    = "20191105000000Z0" fullword
    $s6    = "ZTSN5boost18thread" fullword
    $s7    = "textForMessageInDraggedView" fullword
    $s8    = "EnterModifiedCompliance" fullword
    $s9    = "RequestFPGACount" fullword
    $s10   = "ZBLocalizationContext" fullword
    $s11   = "AECreateAppleEvent" fullword
    $s12   = "isJavaInstalledInternal" fullword
    $s13   = "invalidateRestorableUIState" fullword
    $s14   = "setMinimumContentSize" fullword
    $s15   = "KGWindowsController" fullword
    $s16   = "UHAWAVAUATSHXIcHcH" fullword
    $s17   = "UserNotifications" fullword
    $s18   = "linenoiseEditMoveHome" fullword
    $s19   = "140213191008Z0A1" fullword
    $s20   = "callToActionTitleForWelcomeViewController" fullword
    $s21   = "uriuwfgjZasjXujdmwY" fullword
    $s22   = "ZBNTFSVolumeScanner" fullword
    $s23   = "setSuccessSendingHandler" fullword
    $s24   = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s25   = "setSearchProvider" fullword
    $s26   = "140129192647Z0A1" fullword
    $s27   = "350209214036Z0b1" fullword
    $s28   = "scanJSONKeyValueSeparator" fullword
    $s29   = "CFStringMakeConstantString" fullword
    $s30   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s31   = "respondsToSelector" fullword
    $s32   = "KhfCECHKJKnKtDkW" fullword
    $s33   = "StringCharCodeAt" fullword
    $s34   = "arrayWithObjects" fullword
    $s35   = "HMHMHMHMHMHMHMHMHMH" fullword
    $s36   = "enumerationMutation" fullword
    $s37   = "9allocatorIcEEEC1ERKS5" fullword
    $s38   = "UHAWAVAUATSHHHuE" fullword
    $s39   = "CFConstantStringClassReference" fullword
    $s40   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s41   = "ApplicationServices" fullword
    $s42   = "UHAWAVAUATSH8IIHH" fullword
    $s43   = "cCFAttributedStringMBS" fullword
    $s44   = "SMSTSoSSSSSSSS7U" fullword
    $s45   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s46   = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s47   = "IntermediateBuildFilesPath" fullword
    $s48   = "retainAutoreleasedReturnValue" fullword
    $s49   = "CFNumberGetValue" fullword
    $s50   = "0123456789abcdef" fullword
    $s51   = "N5boost9exceptionE" fullword
    $s52   = "ZN9QListData11shared" fullword
    $s53   = "HEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEgqV" fullword
    $s54   = "objectForKeyedSubscript" fullword
    $s55   = "UHAWAVAUATSPAAII" fullword
    $s56   = "ellipticcurvelist" fullword
    $s57   = "localizedStringForKey" fullword
    $s58   = "UIViewController" fullword
    $s59   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s60   = "dataWithContentsOfFile" fullword
    $s61   = "traitsIcEEE3putEc" fullword
    $s62   = "lswiftObjectiveC" fullword
    $s63   = "DefaultRuneLocale" fullword
    $s64   = "ShCsSwSzfKpADKfADCNK" fullword
    $s65   = "completionHandler" fullword
    $s66   = "PrivateFrameworks" fullword
    $s67   = "HMHMHMHMHMHMHMHMH" fullword
    $s68   = "NSNotificationCenter" fullword
    $s69   = "NSUndoManagerProxy" fullword
    $s70   = "libswiftDispatch" fullword
    $s71   = "UHAWAVAUATSH8IHH" fullword
    $s72   = "CFStringCreateWithCString" fullword
    $s73   = "NSAddressOfSymbol" fullword
    $s74   = "9allocatorIcEEE6insertEmPKcm" fullword
    $s76   = "copyElephantBrain" fullword
    $s77   = "replaceCharactersInRange" fullword
    $s78   = "UHAWAVAUATSPIIHt" fullword
    $s79   = "webScriptNameForSelector" fullword
    $s80   = "UHAWAVAUATSPIHIH" fullword
    $s81   = "IHEHEHEHEHEHEHEL" fullword
    $s83   = "ZN9QListData7disposeEPNS" fullword
    $s84   = "FromStringAndSize" fullword
    $s85   = "NSAutoreleasePool" fullword
    $s86   = "createFileAtPath" fullword
    $s87   = "HEHEHEHEHEHEHEHE" fullword
    $s88   = "fileExistsAtPath" fullword
    $s89   = "CFArrayGetValueAtIndex" fullword
    $s90   = "loadWeakRetained" fullword
    $s91   = "stringWithFormat" fullword
    $s92   = "getInitializedObjCClass" fullword
    $s93   = "NSConcreteGlobalBlock" fullword
    $s94   = "UHAWAVAUATSH8HIH" fullword
    $s95   = "CFURLCopyFileSystemPath" fullword
    $s96   = "NetworkExtension" fullword
    $s97   = "DisableThreadLibraryCalls" fullword
    $s99   = "debugDescription" fullword
    $s100  = "CFStringGetCString" fullword
    $s101  = "SystemConfiguration" fullword
    $s102  = "category23default" fullword
    $s103  = "ServiceManagement" fullword
    $s104  = "libswiftCoreFoundation" fullword
    $s105  = "removeObjectForKey" fullword
    $s106  = "numberWithDouble" fullword
    $s107  = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s108  = "CGPathCreateMutable" fullword
    $s109  = "ZTSN5boost9exceptionE" fullword
    $s110  = "JSValueMakeUndefined" fullword
    $s111  = "autoreleaseReturnValue" fullword
    $s112  = "retainAutorelease" fullword
    $s113  = "MobileCoreServices" fullword
    $s114  = "DEDEDEDEDEDEDEDE9E" fullword
    $s115  = "iPhoneSimulator10" fullword
    $s116  = "kCFAllocatorDefault" fullword
    $s117  = "intrinsicContentSize" fullword
    $s118  = "retainAutoreleaseReturnValue" fullword
    $s119  = "ImageCaptureCore" fullword
    $s122  = "NSStringFromClass" fullword
    $s125  = "9allocatorIcEEEE" fullword
    $s126  = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s127  = "OSAtomicDecrement32" fullword
    $s220  = "spDkrKTDKFCLC8CXD" fullword
    $s227  = "traitsIcEEE9showmanycEv" fullword
    $s229  = "ZN16QLoggingCategoryD1Ev" fullword
    $s232  = "getTupleTypeMetadata2" fullword
    $s233  = "expectedContentLength" fullword
    $s234  = "convertBoolToObjCBoolyAA0eF0VSbF" fullword
    $s235  = "autoreleasePoolPop" fullword
    $s238  = "alSourceQueueBuffers" fullword
    $s241  = "IOIteratorIsValid" fullword
    $s242  = "CFBundleShortVersionString" fullword
    $s244  = "CFURLGetFileSystemRepresentation" fullword
    $s246  = "UHAWAVAUATSPAIIB" fullword
    $s248  = "IOServiceGetMatchingServices" fullword
    $s250  = "getImplementation" fullword
    $s253  = "mediumspringgreen" fullword
    $s255  = "GetEnvironmentVariable" fullword
    $s257  = "glFramebufferTextureLayer" fullword
    $s260  = "NSFetchedPropertyDescription" fullword
    $s262  = "resignFirstResponder" fullword
    $s264  = "UHAWAVAUATSH8IIH" fullword
    $s265  = "9allocatorIcEEEEPNS0" fullword
    $s281  = "CFBundleIdentifier" fullword
    $s282  = "UHAWAVAUATSPIIID" fullword
    $s365  = "previousblockhash" fullword
    $s370  = "15mutex6unlockEv" fullword
    $s373  = "CFBundleGetVersionNumber" fullword
    $s379  = "UHAWAVAUATSPIHIIH" fullword
    $s424  = "CFBundleCopyResourceURL" fullword
    $s426  = "crossCertificatePair" fullword
    $s454  = "GenerateConnectionID" fullword
    $s472  = "ZN5xmrig9Arguments3addEPKc" fullword
    $s480  = "NSAssertionHandler" fullword
    $s483  = "libswiftCoreGraphics" fullword
    $s500  = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s513  = "IOCreatePlugInInterfaceForService" fullword
    $s517  = "NSLayoutConstraint" fullword
    $s519  = "sharedApplication" fullword
    $s523  = "updateBackupGroupsCount" fullword
    $s524  = "bundleIdentifier" fullword
    $s525  = "ZBNetworkReachability" fullword
    $s536  = "CGContextRelease" fullword
    $s544  = "kZBZeoAccountLoggedOutNotification" fullword
    $s545  = "isLifetimeEnabled" fullword
    $s554  = "stringWithUTF8String" fullword
    $s555  = "CFDictionaryCreateMutable" fullword
    $s557  = "IOPlatformExpertDevice" fullword
    $s591  = "18numpunctIcE12do" fullword
    $s592  = "ZTIN10CryptoNote24JsonInputValueSerializerE" fullword
    $s602  = "NSMutableURLRequest" fullword
    $s604  = "UIApplicationDidEnterBackgroundNotification" fullword
    $s607  = "setStandardOutput" fullword
    $s611  = "initWithIdentifier" fullword
    $s631  = "localizedCaseInsensitiveCompare" fullword
    $s636  = "terminationStatus" fullword
    $s643  = "onAllAppsChanged" fullword
    $s644  = "copyClassNamesForImage" fullword
    $s645  = "kZBVTUpdateMethodDownloadAndReveal" fullword
    $s646  = "columnIndexForName" fullword
    $s647  = "CFBundleInfoDictionaryVersion" fullword
    $s650  = "connectionDidFinishLoading" fullword
    $s652  = "stringByAppendingPathComponent" fullword
    $s654  = "G16ComparisonResultOtF" fullword
    $s655  = "countByEnumeratingWithState" fullword
    $s656  = "CSo12NSDictionary" fullword
    $s659  = "fileHandleForWriting" fullword
    $s660  = "isItemExpandable" fullword
    $s674  = "enumerateObjectsUsingBlock" fullword
    $s675  = "characterIsMember" fullword
    $s676  = "initWithContentsOfURL" fullword
    $s681  = "numberWithUnsignedLong" fullword
    $s683  = "systemFontOfSize" fullword
    $s686  = "dictionaryWithContentsOfFile" fullword
    $s688  = "AuthorizationFree" fullword
    $s689  = "inManagedObjectContext" fullword
    $s695  = "timeIntervalSinceDate" fullword
    $s704  = "NSOperationQueue" fullword
    $s713  = "cancelAllOperations" fullword
    $s715  = "stringWithString" fullword
    $s721  = "getblocktemplate" fullword
    $s722  = "ZBSystemInformation" fullword
    $s723  = "dictionaryWithJSONString" fullword
    $s724  = "AssemblyProductAttribute" fullword
    $s726  = "dataTaskWithRequest" fullword
    $s727  = "DraggingViewNotificationIcon" fullword
    $s728  = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s729  = "270201221215Z0y1" fullword
    $s733  = "certificationauthority" fullword
    $s734  = "componentsSeparatedByString" fullword
    $s735  = "cancelButtonTitle" fullword
    $s736  = "IORegistryEntryGetParentEntry" fullword
    $s740  = "certificateauthority" fullword
    $s743  = "assertionFailure" fullword
    $s756  = "numberWithUnsignedInteger" fullword
    $s763  = "SecItemCopyMatching" fullword
    $s764  = "isYahooSearchURL" fullword
    $s767  = "executeWithPrivileges" fullword
    $s768  = "UHAWAVAUATSPDEAI" fullword
    $s769  = "20160507105842Z0" fullword
    $s770  = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s771  = "certificateauthority0" fullword
    $s773  = "setPreferredContentSize" fullword
    $s777  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s778  = "scheduledTimerWithTimeInterval" fullword
    $s779  = "fileHandleForReading" fullword
    $s781  = "arrayWithCapacity" fullword
    $s782  = "CreateDeviceAsyncEventSource" fullword
    $s784  = "substringToIndex" fullword
    $s785  = "191127221001Z0A1" fullword
    $s786  = "addUndeleterFilesRecovered" fullword
    $s788  = "SecTransformExecute" fullword
    $s790  = "191128154500Z0A1" fullword
    $s792  = "UHAWAVAUATSPIIAAHtJH" fullword
    $s796  = "IORegistryEntryCreateCFProperty" fullword
    $s798  = "getMethodDescription" fullword
    $s803  = "CFBundleCopyBundleURL" fullword
    $s804  = "ZN9QListData6appendERKS" fullword
    $s811  = "IOHIDElementGetLogicalMax" fullword
    $s812  = "CFStreamCreatePairWithSocket" fullword
    $s813  = "140305162647Z0A1" fullword
    $s856  = "conformsToProtocolEPKNS" fullword
    $s862  = "200219223002Z0B1" fullword
    $s868  = "20191001103003Z0" fullword
    $s890  = "fHSUATAUAVIHHIHIHD" fullword
    $s894  = "lengthOfBytesUsingEncoding" fullword
    $s898  = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s915  = "operatingSystemVersionString" fullword
    $s919  = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s1007 = "componentsJoinedByString" fullword
    $s1022 = "numberWithUnsignedInt" fullword
    $s1029 = "NSStringPboardType" fullword
    $s1038 = "initWithSuiteName" fullword
    $s1045 = "redirectResponse" fullword
    $s1068 = "checkForUpdatesInBackground" fullword
    $s1099 = "launchJavaApplication" fullword
    $s1122 = "EntryPointNotFoundException" fullword
    $s1123 = "didEndDisplayingHeaderView" fullword
    $s1127 = "19btSingleRayCallback" fullword
    $s1153 = "ASASASASASASASASASASB" fullword
    $s1156 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1158 = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s1204 = "ZNK5boost13match" fullword
    $s1208 = "ZGVZN5boost10filesystem6detail8dot" fullword
    $s1210 = "N5boost9gregorian15bad" fullword
    $s1233 = "replaceObjectAtIndex" fullword
    $s1235 = "fetchCompletionHandler" fullword
    $s1238 = "replacementString" fullword
    $s1241 = "initWithCapacity" fullword
    $s1244 = "didUpdateUserActivity" fullword
    $s1245 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1247 = "NSAppleEventManager" fullword
    $s1260 = "runningApplications" fullword
    $s1267 = "withIntermediateDirectories" fullword
    $s1285 = "timerWithTimeInterval" fullword
    $s1313 = "dataAttributeWithTag" fullword
    $s1314 = "CGContextFillPath" fullword
    $s1315 = "setMinimizeButton" fullword
    $s1320 = "tIvPFvP11WalletModelP7CWalletRKNS" fullword
    $s1321 = "34MutableTransactionSignatureCreator" fullword
    $s1336 = "UIApplicationDelegate" fullword
    $s1337 = "deletedMethodError" fullword
    $s1338 = "XARCSARCSASASATASATAp" fullword
    $s1339 = "registerClassPair" fullword
    $s1350 = "shouldChangeCharactersInRange" fullword
    $s1351 = "0xbd34a880be0b53f3" fullword
    $s1364 = "tappedOnInstallSSHInfoButton" fullword
    $s1366 = "reachabilityWithHostName" fullword
    $s1372 = "isDescendantOfView" fullword
    $s1380 = "NSURLSessionDataDelegate" fullword
    $s1385 = "setTitleBarEndColor" fullword
    $s1399 = "RARARARARARARARARARAZAp" fullword
    $s1404 = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s1410 = "userInterfaceIdiom" fullword
    $s1411 = "constructInstance" fullword
    $s1418 = "commitPreviewingViewController" fullword
    $s1435 = "applicationDockMenu" fullword
    $s1437 = "JSValueMakeBoolean" fullword
    $s1438 = "kMKAlertNotificationServiceName" fullword
    $s1443 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1445 = "SUFileOpRemoveCommand" fullword
    $s1446 = "makeNewConnection" fullword
    $s1447 = "shouldSaveApplicationState" fullword
    $s1448 = "kMDItemWhereFroms" fullword
    $s1452 = "ZL12cxxConstructP11objc" fullword
    $s1453 = "addEntriesFromDictionaryP11objc" fullword
    $s1460 = "objectAtIndexedSubscriptP7NSArrayP13objc" fullword
    $s1466 = "unzGoToFilePos64" fullword
    $s1478 = "collectingEnabled" fullword
    $s1487 = "appropriateForDirectoryURL" fullword
    $s1511 = "conformsToProtocol" fullword
    $s1512 = "RGp0SARARARARARA" fullword
    $s1514 = "objectForKeyP11objc" fullword
    $s1519 = "kMKNotificationActionReviewActionIdentifier" fullword
    $s1523 = "shouldDragDocumentWithEvent" fullword
    $s1524 = "readDataOfLength" fullword
    $s1525 = "setWorkspaceSessionActive" fullword
    $s1529 = "NSDistributedNotificationCenter" fullword
    $s1540 = "stringWithCapacity" fullword
    $s1551 = "delegateHandlesKey" fullword
    $s1553 = "backingScaleFactor" fullword
    $s1569 = "runningApplicationWithProcessIdentifier" fullword
    $s1572 = "CGRectContainsPoint" fullword
    $s1579 = "NSDraggingSession" fullword
    $s1582 = "autoreleasePoolPushv" fullword
    $s1591 = "contentsOfDirectoryAtPath" fullword
    $s1592 = "applicationWillHide" fullword
    $s1605 = "CLSURLSessionConfiguration" fullword
    $s1608 = "indexPathForCell" fullword
    $s1609 = "applicationWillUnhide" fullword
    $s1612 = "addScriptMessageHandler" fullword
    $s1613 = "setAuthenticationPrompt" fullword
    $s1614 = "301231000000Z0s1" fullword
    $s1615 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1616 = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s1619 = "whuplqdwhSurfhvv" fullword
    $s1637 = "matchForPredicate" fullword
    $s1654 = "ConnectionProvider" fullword
    $s1659 = "selectorPFP11objc" fullword
    $s1686 = "CGContextFillRect" fullword
    $s1687 = "kSMDomainSystemLaunchd" fullword
    $s1690 = "applicationDidResignActive" fullword
    $s1692 = "kZBVTNotifiedVersionKey" fullword
    $s1693 = "ZL20fixStringForCoreDataP11objc" fullword
    $s1702 = "createDirectoryAtURL" fullword
    $s1721 = "connectionRequired" fullword
    $s1723 = "ATEContentBlockersRulesWereSet" fullword
    $s1743 = "setAttributedTitle" fullword
    $s1748 = "applicationDidUnhide" fullword
    $s1752 = "SecStaticCodeCreateWithPath" fullword
    $s1753 = "applicationShouldOpenUntitledFile" fullword
    $s1754 = "defaultConfiguration" fullword
    $s1756 = "didDismissWithButtonIndex" fullword
    $s1762 = "includingPropertiesForKeys" fullword
    $s1766 = "enumerateKeysAndObjectsUsingBlock" fullword
    $s1769 = "NSRunningApplication" fullword
    $s1778 = "ZL19transcribeProtocolsP10objc" fullword
    $s1793 = "NSUserNotificationCenterDelegate" fullword
    $s1794 = "componentsSeparatedByCharactersInSet" fullword
    $s1801 = "seekToFileOffset" fullword
    $s1802 = "N7cocos2d7network13IDownloadTaskE" fullword
    $s1803 = "UIGestureRecognizer" fullword
    $s1805 = "AudioConverterGetProperty" fullword
    $s1817 = "ponponqqtsrtsruuxwvwvyy" fullword
    $s1822 = "DEISHUISHUISHxMLH" fullword
    $s1834 = "viewForHeaderInSection" fullword
    $s1835 = "didFailToRegisterForRemoteNotificationsWithError" fullword

  condition:
    ((#s0 <= 3.5)
      and ((#s1 <= 0.5)
        and ((#s2 <= 0.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 1.0)
              and ((#s5 <= 0.5)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 2.5)
                            and ((#s12 <= 1.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 0.5)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 1.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 0.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 0.5)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 1.5)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 3.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 3.0)
                                                                                and ((#s38 <= 0.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 1.0)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 1.0)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 1.0)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((filesize <= 50006.0)
                                                                                                                                                            and ((#s76 <= 1.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 1.0)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 0.5)
                                                                                                                                                                        and ((#s37 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 1.0)
                                                                                                                                                                                and ((#s86 <= 0.5)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 1.0)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((#s92 <= 0.5)
                                                                                                                                                                                              and ((#s93 <= 0.5)
                                                                                                                                                                                                and ((#s94 <= 0.5)
                                                                                                                                                                                                  and ((#s95 <= 0.5)
                                                                                                                                                                                                    and ((#s96 <= 1.0)
                                                                                                                                                                                                      and ((#s97 <= 1.0)
                                                                                                                                                                                                        and ((#s29 <= 0.5)
                                                                                                                                                                                                          and ((#s99 <= 0.5)
                                                                                                                                                                                                            and ((#s100 <= 0.5)
                                                                                                                                                                                                              and ((#s101 <= 1.5)
                                                                                                                                                                                                                and ((#s102 <= 3.0)
                                                                                                                                                                                                                  and ((#s103 <= 1.0)
                                                                                                                                                                                                                    and ((#s104 <= 0.5)
                                                                                                                                                                                                                      and ((#s105 <= 0.5)
                                                                                                                                                                                                                        and ((#s106 <= 0.5)
                                                                                                                                                                                                                          and ((#s107 <= 0.5)
                                                                                                                                                                                                                            and ((#s108 <= 0.5)
                                                                                                                                                                                                                              and ((#s109 <= 0.5)
                                                                                                                                                                                                                                and ((#s110 <= 1.0)
                                                                                                                                                                                                                                  and ((#s111 <= 0.5)
                                                                                                                                                                                                                                    and ((#s112 <= 0.5)
                                                                                                                                                                                                                                      and ((#s113 <= 0.5)
                                                                                                                                                                                                                                        and ((#s114 <= 0.5)
                                                                                                                                                                                                                                          and ((#s115 <= 0.5)
                                                                                                                                                                                                                                            and ((#s116 <= 1.0)
                                                                                                                                                                                                                                              and ((#s117 <= 2.0)
                                                                                                                                                                                                                                                and ((#s118 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s119 <= 1.0)
                                                                                                                                                                                                                                                    and ((filesize > 4222.0)
                                                                                                                                                                                                                                                      and ((#s122 <= 0.5)
                                                                                                                                                                                                                                                        and ((filesize > 4236.0)
                                                                                                                                                                                                                                                          and ((#s125 <= 1.0)
                                                                                                                                                                                                                                                            and ((#s126 <= 1.0)
                                                                                                                                                                                                                                                              and ((#s127 <= 0.5)
                                                                                                                                                                                                                                                                and ((filesize <= 16444.0)
                                                                                                                                                                                                                                                                  and ((filesize <= 5210.0)
                                                                                                                                                                                                                                                                    and ((filesize > 5176.0)
                                                                                                                                                                                                                                                                    )) or (filesize > 16444.0)
                                                                                                                                                                                                                                                                  and ((filesize <= 16478.0)
                                                                                                                                                                                                                                                                    or (filesize > 16478.0)
                                                                                                                                                                                                                                                                    and ((filesize <= 26130.0)
                                                                                                                                                                                                                                                                      and ((filesize <= 26048.0)
                                                                                                                                                                                                                                                                        and ((filesize <= 25136.0)
                                                                                                                                                                                                                                                                          and ((filesize > 18966.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 19068.0)
                                                                                                                                                                                                                                                                              or (filesize > 19068.0)
                                                                                                                                                                                                                                                                              and ((filesize <= 21374.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 21250.0)
                                                                                                                                                                                                                                                                                  and ((filesize > 20788.0)
                                                                                                                                                                                                                                                                                    and ((filesize <= 20802.0)
                                                                                                                                                                                                                                                                                      or (filesize > 20802.0)
                                                                                                                                                                                                                                                                                      and ((filesize > 21044.0)
                                                                                                                                                                                                                                                                                        and ((filesize <= 21100.0)
                                                                                                                                                                                                                                                                                        )))) or (filesize > 21250.0)
                                                                                                                                                                                                                                                                                )))) or (filesize > 25136.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 25232.0)
                                                                                                                                                                                                                                                                          )) or (filesize > 26048.0)
                                                                                                                                                                                                                                                                      ))))))))))))))) or (#s114 > 0.5)
                                                                                                                                                                                                                                        ))))))))))))) or (#s101 > 1.5)
                                                                                                                                                                                                                and ((#s101 <= 2.5)
                                                                                                                                                                                                                  and ((#s103 <= 1.0)
                                                                                                                                                                                                                    and ((#s113 <= 1.0)
                                                                                                                                                                                                                      and ((filesize > 17996.0)
                                                                                                                                                                                                                        and ((filesize <= 19830.0)
                                                                                                                                                                                                                        ))))))))))))))))))) or (#s87 > 0.5)
                                                                                                                                                                                  )))))) or (#s81 > 0.5)
                                                                                                                                                                      ))))) or (#s76 > 1.5)
                                                                                                                                                            ) or (filesize > 50006.0)
                                                                                                                                                            and ((filesize <= 50212.0)
                                                                                                                                                              and ((#s220 <= 0.5)
                                                                                                                                                                and ((filesize <= 50174.5)
                                                                                                                                                                  or (filesize > 50174.5)
                                                                                                                                                                  and ((filesize > 50178.5)
                                                                                                                                                                  )) or (#s220 > 0.5)
                                                                                                                                                              ) or (filesize > 50212.0)
                                                                                                                                                              and ((#s227 <= 0.5)
                                                                                                                                                                and ((#s100 <= 0.5)
                                                                                                                                                                  and ((#s229 <= 1.0)
                                                                                                                                                                    and ((#s94 <= 0.5)
                                                                                                                                                                      and ((#s80 <= 0.5)
                                                                                                                                                                        and ((#s232 <= 1.0)
                                                                                                                                                                          and ((#s233 <= 0.5)
                                                                                                                                                                            and ((#s234 <= 0.5)
                                                                                                                                                                              and ((#s235 <= 0.5)
                                                                                                                                                                                and ((#s96 <= 1.5)
                                                                                                                                                                                  and ((#s113 <= 1.0)
                                                                                                                                                                                    and ((#s238 <= 1.0)
                                                                                                                                                                                      and ((#s84 <= 0.5)
                                                                                                                                                                                        and ((#s126 <= 1.0)
                                                                                                                                                                                          and ((#s241 <= 0.5)
                                                                                                                                                                                            and ((#s242 <= 0.5)
                                                                                                                                                                                              and ((#s127 <= 1.5)
                                                                                                                                                                                                and ((#s244 <= 0.5)
                                                                                                                                                                                                  and ((#s37 <= 1.0)
                                                                                                                                                                                                    and ((#s246 <= 0.5)
                                                                                                                                                                                                      and ((#s107 <= 0.5)
                                                                                                                                                                                                        and ((#s248 <= 1.0)
                                                                                                                                                                                                          and ((#s92 <= 1.0)
                                                                                                                                                                                                            and ((#s250 <= 0.5)
                                                                                                                                                                                                              and ((#s89 <= 0.5)
                                                                                                                                                                                                                and ((#s103 <= 1.0)
                                                                                                                                                                                                                  and ((#s253 <= 0.5)
                                                                                                                                                                                                                    and ((#s115 <= 11.0)
                                                                                                                                                                                                                      and ((#s255 <= 1.0)
                                                                                                                                                                                                                        and ((#s101 <= 1.0)
                                                                                                                                                                                                                          and ((#s257 <= 0.5)
                                                                                                                                                                                                                            and ((#s11 <= 0.5)
                                                                                                                                                                                                                              and ((#s97 <= 0.5)
                                                                                                                                                                                                                                and ((#s260 <= 1.0)
                                                                                                                                                                                                                                  and ((filesize <= 173138.0)
                                                                                                                                                                                                                                    and ((#s262 <= 0.5)
                                                                                                                                                                                                                                      and ((#s93 <= 0.5)
                                                                                                                                                                                                                                        and ((#s264 <= 0.5)
                                                                                                                                                                                                                                          and ((#s265 <= 0.5)
                                                                                                                                                                                                                                            and ((#s125 <= 0.5)
                                                                                                                                                                                                                                              and ((filesize <= 79752.0)
                                                                                                                                                                                                                                                and ((filesize <= 79704.0)
                                                                                                                                                                                                                                                  and ((filesize > 71036.0)
                                                                                                                                                                                                                                                    and ((filesize <= 71184.0)
                                                                                                                                                                                                                                                    )) or (filesize > 79704.0)
                                                                                                                                                                                                                                                ))))))) or (filesize > 173138.0)
                                                                                                                                                                                                                                    and ((#s281 <= 0.5)
                                                                                                                                                                                                                                      and ((#s282 <= 0.5)
                                                                                                                                                                                                                                        and ((#s264 <= 0.5)
                                                                                                                                                                                                                                          and ((filesize <= 173876.0)
                                                                                                                                                                                                                                            or (filesize > 173876.0)
                                                                                                                                                                                                                                            and ((#s125 <= 0.5)
                                                                                                                                                                                                                                              and ((filesize > 457316.0)
                                                                                                                                                                                                                                                and ((#s33 <= 0.5)
                                                                                                                                                                                                                                                  and ((filesize <= 462014.0)
                                                                                                                                                                                                                                                    or (filesize > 462014.0)
                                                                                                                                                                                                                                                    and ((filesize <= 624134.0)
                                                                                                                                                                                                                                                      and ((filesize <= 611308.0)
                                                                                                                                                                                                                                                        and ((filesize <= 467548.0)
                                                                                                                                                                                                                                                          and ((filesize > 465502.0)
                                                                                                                                                                                                                                                          )) or (filesize > 611308.0)
                                                                                                                                                                                                                                                      ) or (filesize > 624134.0)
                                                                                                                                                                                                                                                      and ((filesize > 1677491.5)
                                                                                                                                                                                                                                                        and ((filesize <= 1830813.5)
                                                                                                                                                                                                                                                        )))))))))))))))) or (#s101 > 1.0)
                                                                                                                                                                                                                          and ((filesize > 586212.0)
                                                                                                                                                                                                                            and ((filesize <= 624612.0)
                                                                                                                                                                                                                            ))))))))))))))))))))) or (#s113 > 1.0)
                                                                                                                                                                                    and ((filesize > 2068452.0)
                                                                                                                                                                                      and ((filesize <= 5001522.0)
                                                                                                                                                                                      )))))))) or (#s80 > 0.5)
                                                                                                                                                                        and ((filesize > 3230809.0)
                                                                                                                                                                        ))))))))))))))) or (#s67 > 0.5)
                                                                                                                                          ))) or (#s64 > 0.5)
                                                                                                                                    ) or (#s63 > 0.5)
                                                                                                                                    and ((#s365 <= 1.0)
                                                                                                                                      and ((#s84 <= 0.5)
                                                                                                                                        and ((#s63 > 1.5)
                                                                                                                                          and ((#s87 <= 1.0)
                                                                                                                                            and ((#s370 <= 1.0)
                                                                                                                                              and ((#s73 <= 0.5)
                                                                                                                                                and ((#s125 <= 1.0)
                                                                                                                                                  and ((#s373 <= 1.0)
                                                                                                                                                    and ((#s100 <= 1.0)
                                                                                                                                                      and ((filesize > 287642.0)
                                                                                                                                                        and ((#s71 <= 0.5)
                                                                                                                                                          and ((#s80 <= 1.0)
                                                                                                                                                            and ((#s379 <= 0.5)
                                                                                                                                                              and ((#s97 <= 1.5)
                                                                                                                                                                and ((#s257 <= 1.0)
                                                                                                                                                                  and ((#s63 <= 3.0)
                                                                                                                                                                    and ((filesize <= 298354.0)
                                                                                                                                                                    ))))))))))) or (#s73 > 0.5)
                                                                                                                                                and ((#s73 <= 1.5)
                                                                                                                                                )))))) or (#s365 > 1.0)
                                                                                                                                    ))))) or (#s59 > 0.5)
                                                                                                                            and ((#s63 <= 1.0)
                                                                                                                              and ((filesize <= 50510.0)
                                                                                                                                or (filesize > 50510.0)
                                                                                                                                and ((filesize > 622711.5)
                                                                                                                                ))))))))) or (#s53 > 0.5)
                                                                                                              ))) or (#s50 > 0.5)
                                                                                                          and ((#s116 <= 0.5)
                                                                                                            and ((#s101 <= 1.0)
                                                                                                              and ((#s264 <= 0.5)
                                                                                                                and ((#s229 <= 1.0)
                                                                                                                  and ((#s424 <= 0.5)
                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                      and ((#s426 <= 1.0)
                                                                                                                        and ((#s73 <= 0.5)
                                                                                                                          and ((#s56 <= 1.0)
                                                                                                                            and ((#s63 <= 0.5)
                                                                                                                              and ((#s99 <= 0.5)
                                                                                                                                and ((#s50 <= 5.0)
                                                                                                                                  and ((filesize <= 31638.0)
                                                                                                                                  ))))))))))))))))) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 0.5)
                                                                                                and ((#s100 <= 0.5)
                                                                                                  and ((#s51 <= 0.5)
                                                                                                    and ((#s101 <= 1.0)
                                                                                                      and ((#s454 > 1.0)
                                                                                                      ))) or (#s100 > 0.5)
                                                                                                  and ((#s49 > 0.5)
                                                                                                    and ((#s50 <= 0.5)
                                                                                                      and ((#s73 <= 0.5)
                                                                                                        and ((filesize > 9065528.0)
                                                                                                        )))))) or (#s44 > 0.5)
                                                                                            ) or (#s43 > 0.5)
                                                                                          )) or (#s41 > 0.5)
                                                                                        and ((#s248 <= 0.5)
                                                                                          and ((#s472 <= 0.5)
                                                                                            and ((#s119 <= 1.0)
                                                                                              and ((#s264 <= 0.5)
                                                                                                and ((#s41 <= 2.5)
                                                                                                  and ((#s52 <= 1.0)
                                                                                                    and ((#s71 <= 0.5)
                                                                                                      and ((#s424 <= 0.5)
                                                                                                        and ((#s116 <= 0.5)
                                                                                                          and ((#s480 <= 1.0)
                                                                                                            and ((filesize <= 30065112.0)
                                                                                                              and ((#s85 <= 0.5)
                                                                                                                and ((#s483 <= 0.5)
                                                                                                                  and ((#s227 <= 1.0)
                                                                                                                    and ((filesize > 2915185.5)
                                                                                                                      and ((#s73 <= 1.5)
                                                                                                                        and ((#s80 > 0.5)
                                                                                                                        )))))) or (filesize > 30065112.0)
                                                                                                            ))))) or (#s52 > 1.0)
                                                                                                    and ((#s500 > 1.0)
                                                                                                      and ((#s94 > 0.5)
                                                                                                      )))))) or (#s472 > 0.5)
                                                                                          ))) or (#s40 > 0.5)
                                                                                    ) or (#s39 > 0.5)
                                                                                    and ((#s480 <= 3.5)
                                                                                      and ((#s50 <= 0.5)
                                                                                        and ((#s513 <= 0.5)
                                                                                          and ((#s88 <= 0.5)
                                                                                            and ((#s57 <= 0.5)
                                                                                              and ((#s242 <= 0.5)
                                                                                                and ((#s517 <= 0.5)
                                                                                                  and ((#s116 <= 0.5)
                                                                                                    and ((#s519 <= 0.5)
                                                                                                      and ((#s90 <= 0.5)
                                                                                                        and ((#s95 <= 0.5)
                                                                                                          and ((#s113 <= 0.5)
                                                                                                            and ((#s523 <= 0.5)
                                                                                                              and ((#s524 <= 0.5)
                                                                                                                and ((#s525 > 1.0)
                                                                                                                )) or (#s523 > 0.5)
                                                                                                            ))))))) or (#s242 > 0.5)
                                                                                                and ((#s536 <= 1.0)
                                                                                                  and ((#s89 > 0.5)
                                                                                                  )))) or (#s88 > 0.5)
                                                                                            and ((#s85 <= 3.5)
                                                                                              and ((#s105 <= 0.5)
                                                                                                and ((#s544 <= 0.5)
                                                                                                  and ((#s545 > 0.5)
                                                                                                  ) or (#s544 > 0.5)
                                                                                                )) or (#s85 > 3.5)
                                                                                              and ((#s88 <= 3.0)
                                                                                              ))) or (#s513 > 0.5)
                                                                                          and ((#s95 <= 0.5)
                                                                                            and ((#s554 <= 0.5)
                                                                                              and ((#s555 > 0.5)
                                                                                                and ((#s557 <= 0.5)
                                                                                                  and ((#s513 <= 1.5)
                                                                                                  )))))) or (#s50 > 0.5)
                                                                                        and ((#s248 <= 1.5)
                                                                                          and ((#s50 <= 1.5)
                                                                                            and ((#s113 <= 1.0)
                                                                                              and ((#s39 > 1.5)
                                                                                                and ((#s426 <= 0.5)
                                                                                                )))) or (#s248 > 1.5)
                                                                                          and ((#s41 <= 2.0)
                                                                                          ))) or (#s480 > 3.5)
                                                                                    )) or (#s38 > 0.5)
                                                                                ) or (#s37 > 3.0)
                                                                                and ((#s265 <= 9.5)
                                                                                  and ((#s282 <= 0.5)
                                                                                    and ((#s61 <= 6.0)
                                                                                      and ((#s555 <= 1.0)
                                                                                        and ((#s74 <= 1.0)
                                                                                          and ((#s536 <= 1.0)
                                                                                            and ((#s42 <= 0.5)
                                                                                              and ((#s89 > 1.0)
                                                                                              ))) or (#s74 > 1.0)
                                                                                          and ((#s591 <= 1.0)
                                                                                            and ((#s592 > 0.5)
                                                                                            ) or (#s591 > 1.0)
                                                                                          )))) or (#s282 > 0.5)
                                                                                    and ((#s264 <= 4.0)
                                                                                    )))) or (#s36 > 0.5)
                                                                              and ((#s602 <= 0.5)
                                                                                and ((#s48 <= 0.5)
                                                                                  and ((#s604 <= 3.0)
                                                                                    and ((#s36 > 1.5)
                                                                                      and ((#s607 <= 0.5)
                                                                                        and ((#s100 <= 1.0)
                                                                                          and ((#s41 <= 1.0)
                                                                                            and ((#s71 <= 0.5)
                                                                                              and ((#s611 <= 0.5)
                                                                                                and ((#s554 > 0.5)
                                                                                                  and ((#s86 <= 0.5)
                                                                                                    and ((#s91 <= 0.5)
                                                                                                    ))))))))))))) or (#s35 > 0.5)
                                                                          ) or (#s34 > 0.5)
                                                                          and ((#s11 <= 1.5)
                                                                            and ((#s86 > 0.5)
                                                                              and ((#s631 <= 0.5)
                                                                                and ((filesize <= 114156.0)
                                                                                ))) or (#s11 > 1.5)
                                                                            and ((#s636 > 3.5)
                                                                            ))) or (#s33 > 3.5)
                                                                        and ((#s45 > 22.0)
                                                                        )) or (#s32 > 0.5)
                                                                    ) or (#s31 > 0.5)
                                                                    and ((#s643 <= 0.5)
                                                                      and ((#s644 <= 0.5)
                                                                        and ((#s645 <= 0.5)
                                                                          and ((#s646 <= 0.5)
                                                                            and ((#s647 <= 2.5)
                                                                              and ((#s58 <= 0.5)
                                                                                and ((#s85 <= 1.5)
                                                                                  and ((#s650 <= 0.5)
                                                                                    and ((#s90 <= 0.5)
                                                                                      and ((#s652 <= 0.5)
                                                                                        and ((#s115 <= 1.0)
                                                                                          and ((#s654 <= 1.0)
                                                                                            and ((#s655 <= 0.5)
                                                                                              and ((#s656 <= 0.5)
                                                                                                and ((#s93 <= 0.5)
                                                                                                  and ((#s101 <= 0.5)
                                                                                                    and ((#s659 <= 0.5)
                                                                                                      and ((#s660 <= 0.5)
                                                                                                        and ((#s39 > 3.0)
                                                                                                        ))))))))))) or (#s650 > 0.5)
                                                                                    and ((#s674 <= 0.5)
                                                                                      and ((#s675 <= 0.5)
                                                                                        and ((#s676 > 0.5)
                                                                                        )))) or (#s85 > 1.5)
                                                                                  and ((#s681 <= 0.5)
                                                                                    and ((#s655 <= 0.5)
                                                                                      and ((#s683 <= 0.5)
                                                                                        and ((#s68 > 1.0)
                                                                                          and ((#s686 > 0.5)
                                                                                            and ((#s688 <= 0.5)
                                                                                              and ((#s689 > 0.5)
                                                                                              )))))) or (#s681 > 0.5)
                                                                                    and ((#s695 <= 0.5)
                                                                                      and ((#s116 > 1.5)
                                                                                        and ((#s105 <= 1.5)
                                                                                        )))))) or (#s647 > 2.5)
                                                                            ) or (#s646 > 0.5)
                                                                            and ((#s704 <= 1.0)
                                                                            )) or (#s645 > 0.5)
                                                                        ) or (#s644 > 0.5)
                                                                        and ((#s636 > 0.5)
                                                                        )) or (#s643 > 0.5)
                                                                    )) or (#s30 > 0.5)
                                                                ) or (#s29 > 1.5)
                                                                and ((#s713 <= 0.5)
                                                                  and ((#s95 <= 0.5)
                                                                    and ((#s715 <= 0.5)
                                                                    )))) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                            and ((#s721 <= 0.5)
                                                              and ((#s722 <= 0.5)
                                                                and ((#s723 <= 1.0)
                                                                  and ((#s724 <= 0.5)
                                                                    and ((#s29 <= 0.5)
                                                                      and ((#s726 <= 2.5)
                                                                        and ((#s727 <= 0.5)
                                                                          and ((#s728 <= 0.5)
                                                                            and ((#s729 <= 0.5)
                                                                              and ((#s524 <= 0.5)
                                                                                and ((#s647 > 0.5)
                                                                                  and ((#s733 <= 0.5)
                                                                                    and ((#s734 <= 0.5)
                                                                                      and ((#s735 <= 2.0)
                                                                                        and ((#s736 <= 1.0)
                                                                                          and ((#s111 > 1.0)
                                                                                            and ((#s242 <= 1.5)
                                                                                              and ((#s740 <= 0.5)
                                                                                                and ((#s34 <= 0.5)
                                                                                                  and ((#s99 <= 1.0)
                                                                                                    and ((#s743 <= 1.5)
                                                                                                      and ((filesize <= 78120.0)
                                                                                                      )))))))))))) or (#s524 > 0.5)
                                                                                and ((#s756 <= 0.5)
                                                                                  and ((#s264 <= 0.5)
                                                                                    and ((#s557 > 0.5)
                                                                                    )))) or (#s729 > 0.5)
                                                                              and ((#s763 <= 2.5)
                                                                                and ((#s764 <= 1.0)
                                                                                  and ((#s282 <= 0.5)
                                                                                    and ((#s647 <= 0.5)
                                                                                      and ((#s767 <= 1.0)
                                                                                        and ((#s768 <= 0.5)
                                                                                          and ((#s769 <= 0.5)
                                                                                            and ((#s770 <= 0.5)
                                                                                              and ((#s771 <= 0.5)
                                                                                                and ((#s480 <= 0.5)
                                                                                                  and ((#s773 <= 0.5)
                                                                                                    and ((#s48 <= 1.5)
                                                                                                      and ((#s536 <= 1.5)
                                                                                                        and ((#s66 <= 0.5)
                                                                                                          and ((#s777 <= 0.5)
                                                                                                            and ((#s778 <= 0.5)
                                                                                                              and ((#s779 <= 0.5)
                                                                                                                and ((filesize <= 85880.0)
                                                                                                                  and ((#s781 <= 0.5)
                                                                                                                    and ((#s782 <= 0.5)
                                                                                                                      and ((#s74 <= 1.0)
                                                                                                                        and ((#s784 <= 0.5)
                                                                                                                          and ((#s785 <= 0.5)
                                                                                                                            and ((#s786 <= 0.5)
                                                                                                                              and ((#s740 <= 0.5)
                                                                                                                                and ((#s788 <= 1.0)
                                                                                                                                  and ((#s554 <= 0.5)
                                                                                                                                    and ((#s790 <= 0.5)
                                                                                                                                      and ((#s555 <= 0.5)
                                                                                                                                        and ((#s792 <= 0.5)
                                                                                                                                          and ((#s103 <= 1.0)
                                                                                                                                            and ((#s122 <= 1.0)
                                                                                                                                              and ((#s676 <= 0.5)
                                                                                                                                                and ((#s796 <= 1.0)
                                                                                                                                                  and ((#s41 <= 1.0)
                                                                                                                                                    and ((#s798 <= 1.0)
                                                                                                                                                      and ((#s125 <= 2.0)
                                                                                                                                                        and ((#s37 <= 1.0)
                                                                                                                                                          and ((#s84 <= 1.0)
                                                                                                                                                            and ((#s235 <= 1.0)
                                                                                                                                                              and ((#s803 <= 0.5)
                                                                                                                                                                and ((#s804 <= 1.0)
                                                                                                                                                                  and ((#s27 > 1.5)
                                                                                                                                                                    and ((#s57 <= 0.5)
                                                                                                                                                                      and ((#s513 <= 2.0)
                                                                                                                                                                        and ((#s99 <= 1.0)
                                                                                                                                                                          and ((#s83 <= 1.0)
                                                                                                                                                                            and ((#s811 <= 1.0)
                                                                                                                                                                              and ((#s812 <= 1.0)
                                                                                                                                                                                and ((#s813 <= 0.5)
                                                                                                                                                                                  and ((#s73 <= 0.5)
                                                                                                                                                                                    and ((#s101 <= 1.0)
                                                                                                                                                                                      and ((filesize <= 28720.0)
                                                                                                                                                                                        and ((#s652 <= 0.5)
                                                                                                                                                                                          and ((#s688 <= 0.5)
                                                                                                                                                                                            and ((#s63 <= 1.0)
                                                                                                                                                                                              and ((filesize > 28672.0)
                                                                                                                                                                                              ) or (#s63 > 1.0)
                                                                                                                                                                                            )))))) or (#s813 > 0.5)
                                                                                                                                                                                )))))))))))))))))))) or (#s792 > 0.5)
                                                                                                                                        ))))) or (#s740 > 0.5)
                                                                                                                                and ((#s519 <= 0.5)
                                                                                                                                  and ((#s37 <= 1.0)
                                                                                                                                    and ((#s39 <= 1.0)
                                                                                                                                      and ((#s856 <= 1.0)
                                                                                                                                        and ((#s89 <= 1.0)
                                                                                                                                          and ((#s41 <= 1.0)
                                                                                                                                            and ((#s107 <= 0.5)
                                                                                                                                              and ((filesize <= 66537.0)
                                                                                                                                                and ((#s101 <= 1.0)
                                                                                                                                                  and ((#s862 <= 0.5)
                                                                                                                                                    and ((filesize <= 27528.0)
                                                                                                                                                    ))) or (filesize > 66537.0)
                                                                                                                                                and ((#s868 <= 0.5)
                                                                                                                                                  and ((filesize <= 76360.0)
                                                                                                                                                  ) or (#s868 > 0.5)
                                                                                                                                                )))))))))) or (#s786 > 0.5)
                                                                                                                            ) or (#s785 > 0.5)
                                                                                                                            and ((#s740 > 0.5)
                                                                                                                            ))) or (#s74 > 1.0)
                                                                                                                      ) or (#s782 > 0.5)
                                                                                                                    ) or (#s781 > 0.5)
                                                                                                                    and ((#s116 > 1.0)
                                                                                                                    )) or (filesize > 85880.0)
                                                                                                                  and ((#s890 <= 0.5)
                                                                                                                    and ((#s244 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s227 <= 0.5)
                                                                                                                          and ((#s894 <= 0.5)
                                                                                                                            and ((#s42 <= 0.5)
                                                                                                                              and ((#s100 <= 0.5)
                                                                                                                                and ((#s519 <= 0.5)
                                                                                                                                  and ((#s898 <= 1.5)
                                                                                                                                    and ((#s248 <= 0.5)
                                                                                                                                      and ((#s555 <= 1.0)
                                                                                                                                        and ((#s804 <= 1.0)
                                                                                                                                          and ((#s27 <= 3.0)
                                                                                                                                            and ((#s655 <= 0.5)
                                                                                                                                              and ((#s41 <= 1.0)
                                                                                                                                                and ((#s500 <= 1.0)
                                                                                                                                                  and ((#s862 <= 0.5)
                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                      and ((#s257 <= 0.5)
                                                                                                                                                        and ((#s55 <= 0.5)
                                                                                                                                                          and ((#s50 <= 0.5)
                                                                                                                                                            and ((#s72 <= 1.0)
                                                                                                                                                              and ((#s51 <= 0.5)
                                                                                                                                                                and ((#s83 <= 1.0)
                                                                                                                                                                  and ((#s652 <= 0.5)
                                                                                                                                                                    and ((#s915 <= 2.0)
                                                                                                                                                                      and ((#s695 <= 0.5)
                                                                                                                                                                        and ((#s125 <= 7.5)
                                                                                                                                                                          and ((#s790 <= 0.5)
                                                                                                                                                                            and ((#s919 <= 0.5)
                                                                                                                                                                              and ((#s740 <= 0.5)
                                                                                                                                                                                and ((#s784 <= 0.5)
                                                                                                                                                                                  and ((#s63 > 1.5)
                                                                                                                                                                                    and ((#s264 <= 0.5)
                                                                                                                                                                                      and ((#s71 <= 0.5)
                                                                                                                                                                                        and ((#s253 <= 1.0)
                                                                                                                                                                                          and ((#s785 <= 0.5)
                                                                                                                                                                                            and ((#s39 <= 1.0)
                                                                                                                                                                                              and ((#s45 <= 1.0)
                                                                                                                                                                                                and ((#s101 <= 1.0)
                                                                                                                                                                                                  and ((#s78 <= 0.5)
                                                                                                                                                                                                    and ((filesize > 456640.0)
                                                                                                                                                                                                      and ((filesize <= 569680.0)
                                                                                                                                                                                                      )))))))))))))))))))))) or (#s50 > 0.5)
                                                                                                                                                            and ((#s27 > 1.5)
                                                                                                                                                              and ((#s52 <= 0.5)
                                                                                                                                                                and ((#s45 <= 0.5)
                                                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                                                    and ((#s63 <= 0.5)
                                                                                                                                                                      and ((#s426 <= 0.5)
                                                                                                                                                                        and ((filesize > 293720.0)
                                                                                                                                                                          and ((#s50 <= 1.5)
                                                                                                                                                                            and ((filesize <= 522792.0)
                                                                                                                                                                            )))))))))))) or (#s80 > 0.5)
                                                                                                                                                      and ((#s45 <= 1.0)
                                                                                                                                                        and ((#s71 <= 0.5)
                                                                                                                                                          and ((#s27 > 1.5)
                                                                                                                                                            and ((#s264 <= 0.5)
                                                                                                                                                              and ((filesize > 244685.5)
                                                                                                                                                                and ((filesize <= 321685.5)
                                                                                                                                                                ))))))))))))))) or (#s898 > 1.5)
                                                                                                                                  )))))))))) or (#s779 > 0.5)
                                                                                                                and ((#s1007 <= 0.5)
                                                                                                                  and ((#s659 <= 0.5)
                                                                                                                    and ((#s248 <= 0.5)
                                                                                                                      and ((#s34 <= 1.5)
                                                                                                                        and ((#s683 <= 0.5)
                                                                                                                          and ((#s686 <= 0.5)
                                                                                                                          ))))))) or (#s778 > 0.5)
                                                                                                              and ((#s41 <= 1.0)
                                                                                                                and ((#s89 <= 1.0)
                                                                                                                  and ((#s1022 > 0.5)
                                                                                                                  ))))) or (#s66 > 0.5)
                                                                                                          and ((#s45 <= 1.5)
                                                                                                            and ((#s1029 <= 0.5)
                                                                                                              and ((#s803 > 2.5)
                                                                                                                and ((#s73 <= 1.0)
                                                                                                                )) or (#s1029 > 0.5)
                                                                                                            )))) or (#s48 > 1.5)
                                                                                                      and ((#s1038 <= 0.5)
                                                                                                        and ((filesize <= 32744.0)
                                                                                                          and ((#s111 <= 1.0)
                                                                                                          )) or (#s1038 > 0.5)
                                                                                                      )) or (#s773 > 0.5)
                                                                                                    and ((#s1045 <= 1.0)
                                                                                                    ))) or (#s771 > 0.5)
                                                                                                and ((#s39 > 1.5)
                                                                                                  and ((#s235 <= 0.5)
                                                                                                    and ((#s60 <= 0.5)
                                                                                                      and ((#s1007 <= 0.5)
                                                                                                        and ((#s778 <= 0.5)
                                                                                                          and ((#s244 <= 1.0)
                                                                                                            and ((#s79 > 0.5)
                                                                                                            ))) or (#s1007 > 0.5)
                                                                                                        and ((#s48 <= 1.0)
                                                                                                          and ((#s655 > 0.5)
                                                                                                          ))) or (#s60 > 0.5)
                                                                                                      and ((#s65 <= 0.5)
                                                                                                        and ((#s242 <= 2.0)
                                                                                                          and ((#s1068 > 1.0)
                                                                                                          ))))))) or (#s770 > 0.5)
                                                                                              and ((#s778 <= 0.5)
                                                                                                and ((#s31 > 2.0)
                                                                                                ))) or (#s769 > 0.5)
                                                                                          ) or (#s768 > 0.5)
                                                                                        ) or (#s767 > 1.0)
                                                                                      ))) or (#s764 > 1.0)
                                                                                ) or (#s763 > 2.5)
                                                                              )) or (#s728 > 0.5)
                                                                          ) or (#s727 > 0.5)
                                                                        ) or (#s726 > 2.5)
                                                                        and ((#s41 > 1.0)
                                                                        )) or (#s29 > 0.5)
                                                                      and ((#s803 <= 1.5)
                                                                        and ((#s255 > 0.5)
                                                                          and ((#s262 > 7.5)
                                                                          )) or (#s803 > 1.5)
                                                                        and ((#s100 > 0.5)
                                                                          and ((#s1099 > 0.5)
                                                                            and ((filesize <= 20408.0)
                                                                            ))))) or (#s724 > 0.5)
                                                                  ) or (#s723 > 1.0)
                                                                ) or (#s722 > 0.5)
                                                              ) or (#s721 > 0.5)
                                                            )) or (#s26 > 0.5)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                  ) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                            and ((#s39 <= 0.5)
                                            )) or (#s18 > 0.5)
                                          and ((#s31 > 0.5)
                                          )) or (#s17 > 1.5)
                                        and ((#s113 <= 1.5)
                                          and ((#s1122 <= 0.5)
                                            and ((#s1123 <= 0.5)
                                              and ((#s104 <= 0.5)
                                                and ((#s108 <= 0.5)
                                                  and ((#s631 <= 0.5)
                                                    and ((#s1127 <= 0.5)
                                                      and ((#s17 <= 3.0)
                                                        and ((#s58 <= 2.0)
                                                          and ((#s704 <= 1.0)
                                                            and ((#s80 <= 0.5)
                                                              and ((#s119 <= 1.0)
                                                                and ((#s93 <= 0.5)
                                                                  and ((#s483 <= 0.5)
                                                                    and ((#s264 <= 0.5)
                                                                      and ((filesize > 20366.0)
                                                                      ))))))))) or (#s1127 > 0.5)
                                                    )))))) or (#s113 > 1.5)
                                          and ((#s1153 <= 2.0)
                                            and ((#s604 <= 0.5)
                                              and ((#s756 <= 0.5)
                                                and ((#s1156 <= 0.5)
                                                  and ((#s655 <= 0.5)
                                                    and ((#s1158 <= 0.5)
                                                      and ((filesize > 8760.0)
                                                        and ((#s104 <= 0.5)
                                                          and ((filesize <= 923346.0)
                                                            and ((#s96 <= 1.0)
                                                              and ((#s70 <= 0.5)
                                                                and ((filesize <= 26556.0)
                                                                )) or (#s96 > 1.0)
                                                              and ((filesize > 10528.0)
                                                                and ((filesize <= 14024.0)
                                                                  and ((filesize <= 12038.0)
                                                                  ) or (filesize > 14024.0)
                                                                  and ((filesize <= 16072.0)
                                                                    or (filesize > 16072.0)
                                                                    and ((filesize > 18120.0)
                                                                    ))))) or (filesize > 923346.0)
                                                          ))) or (#s1158 > 0.5)
                                                    )))))))) or (#s16 > 0.5)
                                    ) or (#s15 > 0.5)
                                  ) or (#s14 > 0.5)
                                ) or (#s13 > 0.5)
                              ) or (#s12 > 1.5)
                            ) or (#s11 > 2.5)
                            and ((#s41 <= 1.0)
                            )) or (#s10 > 0.5)
                        ) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                  ) or (#s6 > 0.5)
                  and ((#s729 <= 0.5)
                    and ((#s122 <= 0.5)
                      and ((#s1204 <= 1.0)
                        and ((#s721 <= 0.5)
                          and ((#s89 <= 1.0)
                            and ((#s919 <= 4.5)
                              and ((#s1208 <= 1.0)
                                and ((#s42 <= 1.5)
                                  and ((#s1210 <= 0.5)
                                    and ((#s109 > 1.5)
                                      and ((#s83 > 1.0)
                                      )) or (#s1210 > 0.5)
                                  )) or (#s1208 > 1.0)
                              ))) or (#s721 > 0.5)
                          and ((#s61 <= 0.5)
                            and ((#s41 <= 2.5)
                            ) or (#s61 > 0.5)
                          )))))) or (#s5 > 0.5)
              ) or (#s4 > 1.0)
            ) or (#s3 > 0.5)
          ) or (#s2 > 0.5)
        ) or (#s1 > 0.5)
        and ((#s1233 <= 0.5)
          and ((#s735 <= 0.5)
            and ((#s1235 <= 0.5)
              and ((#s803 <= 1.5)
                and ((#s41 <= 2.5)
                  and ((#s1238 <= 0.5)
                    and ((#s68 <= 2.5)
                      and ((#s557 <= 0.5)
                        and ((#s1241 <= 0.5)
                          and ((#s100 <= 5.5)
                            and ((#s55 <= 1.0)
                              and ((#s1244 <= 0.5)
                                and ((#s1245 <= 0.5)
                                  and ((#s771 <= 0.5)
                                    and ((#s1247 <= 1.0)
                                      and ((#s729 > 0.5)
                                      )))) or (#s1244 > 0.5)
                                and ((#s636 <= 0.5)
                                  and ((#s125 <= 1.0)
                                    and ((#s65 <= 0.5)
                                      and ((#s689 <= 0.5)
                                        and ((#s45 <= 1.0)
                                          and ((#s1038 <= 0.5)
                                            and ((#s1260 <= 0.5)
                                              and ((#s652 <= 0.5)
                                                and ((#s264 <= 0.5)
                                                  and ((#s235 > 1.0)
                                                  )) or (#s652 > 0.5)
                                                and ((#s1267 > 0.5)
                                                ))) or (#s1038 > 0.5)
                                            and ((#s41 <= 1.0)
                                            )))))) or (#s636 > 0.5)
                                  and ((#s99 <= 1.5)
                                  ))) or (#s55 > 1.0)
                            ) or (#s100 > 5.5)
                          ) or (#s1241 > 0.5)
                          and ((#s652 > 0.5)
                            and ((#s1285 <= 0.5)
                              and ((#s734 <= 0.5)
                                and ((#s1244 > 0.5)
                                ) or (#s734 > 0.5)
                              ) or (#s1285 > 0.5)
                            ))) or (#s557 > 0.5)
                        and ((#s513 <= 1.0)
                          and ((#s63 <= 1.0)
                            and ((#s90 <= 1.0)
                              and ((#s1245 <= 0.5)
                                or (#s1245 > 0.5)
                                and ((#s91 > 0.5)
                                )) or (#s90 > 1.0)
                              and ((#s483 > 0.5)
                              ))))) or (#s68 > 2.5)
                    ) or (#s1238 > 0.5)
                    and ((#s715 > 0.5)
                      and ((#s90 <= 1.0)
                        and ((#s250 > 1.0)
                        )))) or (#s41 > 2.5)
                  and ((#s1313 <= 1.0)
                    and ((#s1314 <= 1.0)
                      and ((#s1315 > 1.5)
                      )) or (#s1313 > 1.0)
                  )) or (#s803 > 1.5)
                and ((#s1320 <= 0.5)
                  and ((#s1321 > 0.5)
                  ) or (#s1320 > 0.5)
                )) or (#s1235 > 0.5)
              and ((#s655 <= 0.5)
                and ((#s519 <= 0.5)
                  and ((#s34 <= 0.5)
                    and ((#s656 <= 0.5)
                      and ((#s62 <= 1.0)
                        and ((#s122 > 1.0)
                        )))) or (#s519 > 0.5)
                  and ((#s1336 <= 4.5)
                    and ((#s1337 <= 1.0)
                      and ((#s1338 <= 0.5)
                        and ((#s1339 <= 1.0)
                          and ((#s1123 <= 0.5)
                            and ((#s88 <= 0.5)
                            )) or (#s1339 > 1.0)
                        ) or (#s1338 > 0.5)
                      ) or (#s1337 > 1.0)
                    ))) or (#s655 > 0.5)
                and ((#s17 <= 1.0)
                  and ((#s1350 <= 0.5)
                    and ((#s1351 <= 0.5)
                      and ((#s1241 <= 0.5)
                        and ((#s112 <= 0.5)
                          and ((#s91 <= 0.5)
                            or (#s91 > 0.5)
                            and ((#s695 > 0.5)
                            )) or (#s112 > 0.5)
                          and ((#s1267 > 0.5)
                          ))) or (#s1351 > 0.5)
                    ) or (#s1350 > 0.5)
                    and ((#s1364 <= 0.5)
                      and ((#s34 <= 0.5)
                        and ((#s1366 <= 0.5)
                        )) or (#s1364 > 0.5)
                    ))))) or (#s735 > 0.5)
            and ((#s1372 <= 0.5)
              and ((#s66 <= 0.5)
                and ((#s604 > 1.0)
                  and ((#s235 > 1.0)
                    and ((#s1366 > 0.5)
                      and ((#s1380 <= 0.5)
                      )))) or (#s66 > 0.5)
              ))) or (#s1233 > 0.5)
          and ((#s1385 <= 0.5)
            and ((#s262 <= 0.5)
              and ((#s674 <= 0.5)
                and ((#s715 <= 0.5)
                  and ((filesize <= 441856.0)
                    and ((#s39 <= 1.5)
                      or (#s39 > 1.5)
                      and ((#s729 > 0.5)
                      )) or (filesize > 441856.0)
                    and ((#s112 > 3.5)
                    )) or (#s715 > 0.5)
                  and ((#s644 <= 0.5)
                    and ((#s1399 > 1.5)
                    ) or (#s644 > 0.5)
                  ))) or (#s262 > 0.5)
              and ((#s1404 <= 0.5)
                and ((#s517 <= 0.5)
                  and ((#s524 <= 4.5)
                    and ((#s68 <= 0.5)
                    ) or (#s524 > 4.5)
                    and ((#s1410 <= 2.5)
                      and ((#s1411 <= 1.0)
                        and ((filesize > 7098608.0)
                        ) or (#s1411 > 1.0)
                      )))) or (#s1404 > 0.5)
                and ((#s1418 > 0.5)
                  and ((#s89 <= 3.0)
                    and ((#s58 <= 16.0)
                      or (#s58 > 16.0)
                      and ((filesize > 18004136.0)
                      )) or (#s89 > 3.0)
                    and ((#s602 <= 9.0)
                      or (#s602 > 9.0)
                      and ((filesize <= 25131192.0)
                      )))))) or (#s1385 > 0.5)
          ))) or (#s0 > 3.5)
      and ((#s106 <= 0.5)
        and ((#s524 <= 0.5)
          and ((#s796 <= 1.0)
            and ((#s1435 <= 0.5)
              and ((#s7 <= 0.5)
                and ((#s1437 <= 1.0)
                  and ((#s1438 <= 1.0)
                    and ((#s544 <= 1.0)
                      and ((#s771 <= 0.5)
                        and ((#s686 <= 0.5)
                          and ((#s232 <= 1.0)
                            and ((#s1443 <= 3.0)
                              and ((#s1038 <= 0.5)
                                and ((#s1445 <= 0.5)
                                  and ((#s1446 <= 0.5)
                                    and ((#s1447 <= 0.5)
                                      and ((#s1448 <= 0.5)
                                        and ((#s704 <= 1.0)
                                          and ((#s118 <= 1.5)
                                            and ((#s99 <= 1.0)
                                              and ((#s1452 <= 1.5)
                                                and ((#s1453 <= 0.5)
                                                  and ((#s93 <= 1.0)
                                                    and ((#s27 <= 0.5)
                                                    ))) or (#s1452 > 1.5)
                                                and ((#s1460 > 1.0)
                                                  and ((filesize <= 67096.0)
                                                    and ((#s740 > 0.5)
                                                    ) or (filesize > 67096.0)
                                                    and ((#s1466 <= 1.0)
                                                      and ((#s112 <= 2.0)
                                                        and ((#s6 <= 1.5)
                                                          and ((#s68 > 1.0)
                                                            and ((#s57 <= 0.5)
                                                              and ((filesize > 124696.0)
                                                              ))))) or (#s1466 > 1.0)
                                                      and ((#s1478 > 1.0)
                                                      )))))))) or (#s1448 > 0.5)
                                      )) or (#s1446 > 0.5)
                                  ) or (#s1445 > 0.5)
                                  and ((#s1487 <= 2.5)
                                    and ((#s282 > 0.5)
                                      and ((filesize <= 105608.0)
                                      )))) or (#s1038 > 0.5)
                                and ((#s104 > 0.5)
                                )))) or (#s686 > 0.5)
                          and ((#s105 <= 0.5)
                            or (#s105 > 0.5)
                            and ((#s643 <= 0.5)
                              and ((#s105 > 4.0)
                                and ((#s652 <= 0.5)
                                  and ((filesize <= 232856.0)
                                  ) or (#s652 > 0.5)
                                )) or (#s643 > 0.5)
                            ))) or (#s771 > 0.5)
                        and ((#s781 <= 0.5)
                          and ((#s1511 <= 0.5)
                            and ((#s1512 > 0.5)
                              and ((#s1514 <= 0.5)
                                and ((filesize <= 42384.0)
                                ))) or (#s1511 > 0.5)
                            and ((#s1519 <= 1.0)
                              and ((#s674 <= 0.5)
                                and ((#s770 <= 1.5)
                                  and ((#s60 <= 0.5)
                                    and ((#s1523 <= 0.5)
                                      and ((#s1524 <= 0.5)
                                        and ((#s1525 <= 0.5)
                                          and ((#s85 <= 2.0)
                                            and ((#s36 > 1.0)
                                              and ((#s1529 > 1.0)
                                              )) or (#s85 > 2.0)
                                          ) or (#s1525 > 0.5)
                                        )))) or (#s770 > 1.5)
                                ) or (#s674 > 0.5)
                              ) or (#s1519 > 1.0)
                            )) or (#s781 > 0.5)
                          and ((#s1540 <= 0.5)
                            and ((#s88 <= 0.5)
                            )))) or (#s544 > 1.0)
                    ) or (#s1438 > 1.0)
                  ) or (#s1437 > 1.0)
                ) or (#s7 > 0.5)
              ) or (#s1435 > 0.5)
              and ((#s734 <= 0.5)
                and ((#s91 <= 0.5)
                  and ((#s1551 <= 0.5)
                    and ((#s111 <= 2.0)
                      and ((#s1553 <= 0.5)
                        and ((#s644 <= 4.0)
                          and ((#s0 > 4.5)
                            and ((#s1244 <= 0.5)
                            )) or (#s644 > 4.0)
                          and ((#s681 > 0.5)
                          ))) or (#s111 > 2.0)
                    )) or (#s91 > 0.5)
                  and ((#s85 <= 2.0)
                  )) or (#s734 > 0.5)
                and ((#s1569 <= 0.5)
                  and ((#s88 <= 0.5)
                    or (#s88 > 0.5)
                    and ((#s1572 <= 1.0)
                      and ((#s122 <= 1.0)
                      ))) or (#s1569 > 0.5)
                ))) or (#s796 > 1.0)
            and ((#s85 <= 2.0)
              and ((#s1579 <= 2.0)
                and ((#s370 <= 1.0)
                  and ((#s734 <= 0.5)
                    and ((#s1582 > 1.5)
                      and ((#s1540 > 0.5)
                      )) or (#s734 > 0.5)
                    and ((#s34 <= 0.5)
                      and ((#s1267 > 0.5)
                      ) or (#s34 > 0.5)
                      and ((#s1591 <= 0.5)
                        and ((#s1592 > 0.5)
                        ) or (#s1591 > 0.5)
                      ))) or (#s370 > 1.0)
                )) or (#s85 > 2.0)
              and ((#s93 > 1.0)
                and ((#s68 <= 1.0)
                )))) or (#s524 > 0.5)
          and ((#s554 <= 0.5)
            and ((#s729 <= 0.5)
              and ((#s1605 <= 9.5)
                and ((#s1411 > 1.0)
                  and ((#s1608 <= 0.5)
                    and ((#s1609 <= 0.5)
                      and ((#s0 > 4.5)
                        and ((#s1612 <= 0.5)
                          and ((#s1613 <= 1.0)
                            and ((#s1614 <= 1.0)
                              and ((#s1615 <= 0.5)
                                and ((#s1616 <= 0.5)
                                ) or (#s1615 > 0.5)
                                and ((#s1619 > 0.5)
                                ))) or (#s1613 > 1.0)
                          ))) or (#s1609 > 0.5)
                      and ((#s39 <= 1.0)
                        and ((#s771 <= 0.5)
                        ) or (#s39 > 1.0)
                        and ((#s652 > 0.5)
                        )))))) or (#s729 > 0.5)
              and ((filesize <= 1022648.0)
                and ((#s1238 <= 0.5)
                  and ((#s1 <= 0.5)
                    and ((#s1637 <= 1.0)
                      and ((#s1523 <= 0.5)
                        and ((#s1267 <= 0.5)
                          and ((#s781 <= 0.5)
                            and ((#s655 > 1.5)
                            ) or (#s781 > 0.5)
                          ) or (#s1267 > 0.5)
                        )) or (#s1637 > 1.0)
                    ) or (#s1 > 0.5)
                    and ((#s784 > 0.5)
                    )) or (#s1238 > 0.5)
                ))) or (#s554 > 0.5)
            and ((#s85 <= 2.5)
              and ((#s1654 <= 0.5)
                and ((#s34 <= 0.5)
                  and ((#s771 <= 0.5)
                    and ((#s36 > 1.5)
                      and ((#s1659 <= 1.0)
                      )) or (#s771 > 0.5)
                  ) or (#s34 > 0.5)
                  and ((#s788 <= 1.0)
                    and ((#s66 <= 0.5)
                      and ((#s784 > 0.5)
                        and ((#s480 <= 1.0)
                          and ((#s93 <= 1.0)
                            or (#s93 > 1.0)
                            and ((#s1233 > 0.5)
                            )))) or (#s66 > 0.5)
                    ))) or (#s1654 > 0.5)
              ) or (#s85 > 2.5)
              and ((#s86 <= 1.5)
                and ((#s803 <= 1.0)
                  and ((#s93 <= 1.0)
                    and ((#s1045 > 0.5)
                    ) or (#s93 > 1.0)
                  )))))) or (#s106 > 0.5)
        and ((#s1686 <= 1.0)
          and ((#s1687 <= 1.0)
            and ((#s631 <= 0.5)
              and ((#s480 <= 1.0)
                and ((#s1690 <= 0.5)
                  and ((#s659 <= 0.5)
                    and ((#s1692 <= 0.5)
                      and ((#s1693 <= 0.5)
                        and ((#s282 <= 0.5)
                          and ((#s784 > 0.5)
                            and ((#s779 > 0.5)
                            )) or (#s282 > 0.5)
                          and ((#s424 <= 1.0)
                            and ((#s72 <= 1.0)
                              and ((#s1702 <= 0.5)
                              )))) or (#s1693 > 0.5)
                        and ((#s88 <= 0.5)
                          and ((#s1233 <= 0.5)
                            and ((#s99 > 1.0)
                              and ((#s115 <= 1.0)
                                and ((#s1659 <= 1.0)
                                )))) or (#s88 > 0.5)
                          and ((#s683 <= 0.5)
                            and ((#s281 > 1.0)
                            ) or (#s683 > 0.5)
                            and ((#s1721 <= 1.5)
                              and ((#s734 <= 0.5)
                                and ((#s1723 > 0.5)
                                )))))) or (#s1692 > 0.5)
                    ) or (#s659 > 0.5)
                    and ((#s1045 <= 1.5)
                    )) or (#s1690 > 0.5)
                  and ((#s524 <= 0.5)
                    and ((#s1512 > 0.5)
                      and ((#s555 <= 1.0)
                        and ((#s740 <= 0.5)
                          and ((filesize <= 1460656.0)
                          ) or (#s740 > 0.5)
                        ))) or (#s524 > 0.5)
                    and ((#s736 <= 2.5)
                      and ((#s1743 <= 0.5)
                        and ((#s778 > 0.5)
                        ) or (#s1743 > 0.5)
                      ) or (#s736 > 2.5)
                      and ((#s1748 > 1.5)
                      )))) or (#s480 > 1.0)
                and ((#s1529 <= 1.0)
                  and ((#s1752 <= 1.0)
                    and ((#s1753 <= 0.5)
                      and ((#s1754 > 3.0)
                        and ((#s1756 <= 0.5)
                          and ((#s644 <= 4.0)
                          ))) or (#s1753 > 0.5)
                      and ((#s49 <= 1.0)
                        and ((#s1762 > 0.5)
                        ))) or (#s1752 > 1.0)
                    and ((#s1766 <= 0.5)
                      and ((#s659 <= 0.5)
                        and ((#s1693 <= 1.5)
                          and ((#s1769 <= 1.0)
                            and ((#s282 > 0.5)
                              and ((filesize <= 209960.0)
                              )))) or (#s659 > 0.5)
                        and ((#s1153 <= 0.5)
                          and ((#s1778 > 1.5)
                            and ((#s790 <= 0.5)
                              and ((#s704 <= 1.0)
                                and ((#s71 <= 0.5)
                                  and ((#s27 > 1.5)
                                    and ((filesize <= 553256.0)
                                    )))))))) or (#s1766 > 0.5)
                    )) or (#s1529 > 1.0)
                  and ((#s1793 <= 0.5)
                    and ((#s1794 <= 0.5)
                    ) or (#s1793 > 0.5)
                  ))) or (#s631 > 0.5)
              and ((#s796 <= 1.0)
                and ((#s480 > 1.0)
                  and ((#s1801 <= 0.5)
                    and ((#s1802 <= 1.5)
                      and ((#s1803 <= 2.5)
                        or (#s1803 > 2.5)
                        and ((#s1805 <= 1.0)
                          and ((#s58 > 9.0)
                          ) or (#s1805 > 1.0)
                          and ((#s118 <= 2.5)
                            and ((filesize <= 16238624.0)
                              and ((#s1156 <= 0.5)
                              ) or (filesize > 16238624.0)
                            ) or (#s118 > 2.5)
                            and ((#s1817 > 1.0)
                            ))))))) or (#s796 > 1.0)
                and ((#s1822 <= 0.5)
                  and ((#s71 <= 0.5)
                  ) or (#s1822 > 0.5)
                ))) or (#s1687 > 1.0)
            and ((#s264 <= 9.0)
              and ((#s1582 <= 1.5)
                and ((#s41 > 1.0)
                ) or (#s1582 > 1.5)
              ))) or (#s1686 > 1.0)
          and ((#s1834 <= 0.5)
            and ((#s1835 > 2.5)
              and ((#s646 > 0.5)
              ))))))
}